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

/// Maximum number of bytes searched for the header/body separator.
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_PARTS: usize = 100;

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
            if parts_processed > MAX_PARTS {
                break;
            }

            let Some((header, body)) = Self::split_message(current_data) else {
                if is_root {
                    return Err(Error::NotEml);
                }
                continue;
            };
            let headers = Self::parse_headers(header);

            if is_root {
                if !Self::valid_header_block(header)
                    || !COMMON_HEADERS.iter().any(|h| headers.contains_key(*h))
                {
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
                let remaining_parts =
                    MAX_PARTS.saturating_sub(parts_processed + stack.len());
                let parts: Vec<&[u8]> = body
                    .split_str(&delimiter)
                    .skip(1)
                    .take(remaining_parts)
                    .collect();
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

    fn split_message(input: &[u8]) -> Option<(&[u8], &[u8])> {
        let prefix = &input[..input.len().min(MAX_HEADER_BYTES)];
        let crlf = prefix.find(b"\r\n\r\n").map(|pos| (pos, 4));
        let lf = prefix.find(b"\n\n").map(|pos| (pos, 2));
        let (pos, separator_len) = match (crlf, lf) {
            (Some(a), Some(b)) => if a.0 <= b.0 { a } else { b },
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return None,
        };

        Some((&input[..pos], &input[pos + separator_len..]))
    }

    /// Checks that the root header block is plausible email syntax, rather
    /// than garbage bytes containing a familiar header later in the block.
    fn valid_header_block(raw: &[u8]) -> bool {
        let mut has_field = false;

        for line in raw.lines() {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.starts_with(b" ") || line.starts_with(b"\t") {
                if !has_field || line.iter().any(|b| b.is_ascii_control() && *b != b'\t') {
                    return false;
                }
                continue;
            }

            let Some((name, value)) = line.split_once_str(b":") else {
                return false;
            };
            if name.is_empty()
                || !name.iter().all(|b| b.is_ascii_graphic())
                || value.iter().any(|b| b.is_ascii_control() && *b != b'\t')
            {
                return false;
            }
            has_field = true;
        }

        has_field
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
