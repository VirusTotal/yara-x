use crate::modules::eml::address::parse_address_list;
use crate::modules::eml::rfc2047::decode_encoded_words;
use crate::modules::protos::eml::{Address, Eml, EmlPart, Header};
use base64::prelude::*;
use bstr::ByteSlice;
use indexmap::IndexMap;

type Headers = IndexMap<Vec<u8>, Vec<Vec<u8>>>;

#[derive(Debug)]
pub enum Error {
    /// The data doesn't look like an email message.
    NotEml,
}

/// Headers that make a piece of data look like an email message. At least
/// one of them must be present.
const COMMON_HEADERS: [&[u8]; 8] = [
    b"from",
    b"to",
    b"subject",
    b"date",
    b"message-id",
    b"received",
    b"mime-version",
    b"content-type",
];

/// An Eml parser
pub struct EmlParser;

// the anatomy of an email can be defined like so:
// headers (check for content-type)
// body
// and nest
//
impl EmlParser {
    /// Parses an EML message.
    pub fn parse(input: &[u8]) -> Result<Eml, Error> {
        let mut result = Eml { is_eml: Some(true), ..Default::default() };

        // stack for processing
        let mut stack: Vec<&[u8]> = vec![input];
        let mut is_root = true;
        // keep track to prevent mime bomb shenanigans
        let mut parts_processed = 0;

        while let Some(current_data) = stack.pop() {
            parts_processed += 1;
            if parts_processed > 100 {
                break;
            }

            let (header, body) = Self::split_message(current_data);
            let headers = Self::parse_headers(header);

            if is_root {
                if !COMMON_HEADERS.iter().any(|h| headers.contains_key(*h)) {
                    return Err(Error::NotEml);
                }
                result.headers = Self::map_to_proto_headers(&headers);
                result.body = Some(body.to_vec());
                result.decoded_body = Self::decode_body(&headers, body);
                result.from = Self::addresses(&headers, b"from");
                result.to = Self::addresses(&headers, b"to");
                result.cc = Self::addresses(&headers, b"cc");
                result.subject = Self::first_header(&headers, b"subject")
                    .map(|v| decode_encoded_words(&v));
                result.message_id = Self::first_header(&headers, b"message-id");
                result.date = Self::first_header(&headers, b"date");
                result.reply_to = Self::addresses(&headers, b"reply-to");
                result.return_path = Self::addresses(&headers, b"return-path")
                    .into_iter()
                    .next()
                    .into();
            }

            // Content-Type should be checked for multipart and boundary
            let boundary = Self::main_value(&headers, b"content-type")
                .filter(|ct| ct.starts_with(b"multipart"))
                .and_then(|_| {
                    Self::param(&headers, b"content-type", b"boundary")
                });

            if let Some(boundary) = boundary {
                let delimiter = [b"--".as_slice(), &boundary].concat();
                // The first element is the preamble, not a part.
                let parts: Vec<&[u8]> =
                    body.split_str(&delimiter).skip(1).collect();
                for part in parts.into_iter().rev() {
                    let trimmed = part.trim();

                    if trimmed.is_empty() || trimmed.starts_with(b"--") {
                        continue;
                    }
                    stack.push(trimmed);
                }
            } else if !is_root {
                let decoded_body = Self::decode_body(&headers, body);
                let size = decoded_body.as_ref().map_or(body.len(), Vec::len);

                result.parts.push(EmlPart {
                    headers: Self::map_to_proto_headers(&headers),
                    body: Some(body.to_vec()),
                    decoded_body,
                    filename: Self::param(
                        &headers,
                        b"content-disposition",
                        b"filename",
                    )
                    .or_else(|| Self::param(&headers, b"content-type", b"name")),
                    disposition: Self::main_value(
                        &headers,
                        b"content-disposition",
                    ),
                    content_type: Self::main_value(&headers, b"content-type"),
                    charset: Self::param(&headers, b"content-type", b"charset"),
                    content_id: Self::first_header(&headers, b"content-id")
                        .map(|v| {
                            v.trim_with(|c| c == '<' || c == '>').to_vec()
                        }),
                    size: Some(size as i64),
                    ..Default::default()
                });
            }
            is_root = false;
        }

        Ok(result)
    }

    fn split_message(input: &[u8]) -> (&[u8], &[u8]) {
        if let Some(pos) = input.find("\r\n\r\n") {
            (&input[..pos], &input[pos + 4..])
        } else if let Some(pos) = input.find("\n\n") {
            (&input[..pos], &input[pos + 2..])
        } else {
            (input, &[][..])
        }
    }

    fn decode_body(headers: &Headers, body: &[u8]) -> Option<Vec<u8>> {
        let enc = headers
            .get(b"content-transfer-encoding".as_slice())
            .and_then(|v| v.first())?;
        match enc.to_ascii_lowercase().as_slice() {
            b"base64" => {
                let cleaned: Vec<u8> = body
                    .iter()
                    .filter(|&&b| !b.is_ascii_whitespace())
                    .cloned()
                    .collect();
                BASE64_STANDARD.decode(cleaned).ok()
            }
            b"quoted-printable" => quoted_printable::decode(
                body,
                quoted_printable::ParseMode::Robust,
            )
            .ok(),
            _ => None,
        }
    }

    /// Returns the first value of the header `name`, which must be lowercase.
    fn first_header(headers: &Headers, name: &[u8]) -> Option<Vec<u8>> {
        headers.get(name)?.first().cloned()
    }

    /// Returns the first value of the header `name` (lowercase) without its
    /// parameters, lowercased: `Text/HTML; charset=x` becomes `text/html`.
    fn main_value(headers: &Headers, name: &[u8]) -> Option<Vec<u8>> {
        let value = Self::first_header(headers, name)?;
        let main = value.split_once_str(";").map_or(&value[..], |(m, _)| m);
        Some(main.trim().to_ascii_lowercase())
    }

    /// Returns the parameter `param_name` of the first value of the header
    /// `header` (lowercase): `param(h, b"content-type", b"charset")`.
    fn param(
        headers: &Headers,
        header: &[u8],
        param_name: &[u8],
    ) -> Option<Vec<u8>> {
        Self::get_mime_param(headers.get(header)?.first()?, param_name)
            .map(<[u8]>::to_vec)
    }

    /// Parses all occurrences of the address header `name` (lowercase).
    fn addresses(headers: &Headers, name: &[u8]) -> Vec<Address> {
        headers
            .get(name)
            .into_iter()
            .flatten()
            .flat_map(|v| parse_address_list(v))
            .collect()
    }

    fn map_to_proto_headers(headers: &Headers) -> Vec<Header> {
        headers
            .iter()
            .flat_map(|(k, values)| {
                values.iter().map(|v| Header {
                    key: Some(k.clone()),
                    value: Some(v.clone()),
                    ..Default::default()
                })
            })
            .collect()
    }

    /// Extract a named parameter value from a MIME header value.
    /// e.g. `get_mime_param(b"multipart/mixed; boundary=abc", b"boundary")` → `Some(b"abc")`
    /// Handles both quoted (`boundary="abc"`) and unquoted (`boundary=abc`) forms.
    /// Case-insensitive matching
    fn get_mime_param<'a>(
        header_value: &'a [u8],
        param_name: &[u8],
    ) -> Option<&'a [u8]> {
        header_value.split_str(b";").skip(1).find_map(|param| {
            let param = param.trim();
            let (name, value) = param.split_once_str(b"=")?;
            if !name.trim().eq_ignore_ascii_case(param_name) {
                return None;
            }
            let value = value.trim();
            let bytes = if value.starts_with(b"\"") {
                value.split_str(b"\"").nth(1)?
            } else {
                value
            };
            if bytes.is_empty() { None } else { Some(bytes) }
        })
    }

    fn parse_headers(headers_raw: &[u8]) -> Headers {
        let mut last_key: Option<Vec<u8>> = None;
        let mut headers = Headers::new();

        for line in headers_raw.lines() {
            if line.starts_with(b" ") || line.starts_with(b"\t") {
                // Continuation of the previous header: unfold it.
                if let Some(last_val) = last_key
                    .as_ref()
                    .and_then(|k| headers.get_mut(k))
                    .and_then(|values| values.last_mut())
                {
                    last_val.push(b' ');
                    last_val.extend_from_slice(line.trim());
                }
            } else if let Some((key, value)) = line.split_once_str(":") {
                let key = key.trim().to_ascii_lowercase();
                let value = value.trim().to_vec();
                headers.entry(key.clone()).or_default().push(value);
                last_key = Some(key);
            }
        }

        headers
    }
}
