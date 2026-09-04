use std::mem;

use crate::modules::protos::eml::{Eml, EmlPart, Header};
use base64::prelude::*;
use bstr::ByteSlice;
use indexmap::IndexMap;
use nom::Err;

// type NomError<'a> = nom::error::Error<&'a [u8]>;

type Headers = IndexMap<Vec<u8>, Vec<Vec<u8>>>;

/// An Eml parser
pub struct EmlParser {
    result: Eml,
}

// the anatomy of an email can be defined like so:
// headers (check for content-type)
// body
// and nest
//
impl EmlParser {
    /// Creates a new parser for Eml files
    pub fn new() -> Self {
        Self { result: Eml::default() }
    }

    pub fn parse<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<Eml, Err<nom::error::Error<&'a [u8]>>> {
        self.result.is_eml = Some(true);

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

            let (header, body) = self.split_message(current_data);
            let headers = self.parse_headers(header);

            if is_root {
                self.result.headers = self.map_to_proto_headers(&headers);
                self.result.body = Some(body.to_vec());
                self.result.decoded_body = self.decode_body(&headers, body);
            }

            // Content-Type should be checked for multipart and boundary
            let mut found_boundary = None;
            if let Some(ct) = headers.get(b"content-type".as_slice()).and_then(|v| v.first()).map(Vec::as_slice) &&
                ct.len() >= 10 && ct[..9].eq_ignore_ascii_case(b"multipart") {
                    // split on ';', find the boundary param by name
                    let boundary_bytes = Self::get_mime_param(ct, b"boundary");

                    if let Some(b) = boundary_bytes {
                        let mut delimiter = b"--".to_vec();
                        delimiter.extend_from_slice(b);
                        found_boundary = Some(delimiter);
                }
            }

            if let Some(delimiter) = found_boundary {
                let parts: Vec<&[u8]> = body.split_str(&delimiter).collect();
                for part in parts.into_iter().rev() {
                    let trimmed = part.trim();

                    if trimmed.is_empty() || trimmed.starts_with(b"--") {
                        continue;
                    }
                    stack.push(trimmed);
                }
            } else if !is_root {
                let filename = headers
                    .get(b"content-disposition".as_slice())
                    .and_then(|v| v.first())
                    .and_then(|v| Self::get_mime_param(v, b"filename"))
                    .or_else(|| {
                        headers
                            .get(b"content-type".as_slice())
                            .and_then(|v| v.first())
                            .and_then(|v| Self::get_mime_param(v, b"name"))
                    })
                    .map(|b| b.to_vec());

                let disposition = headers.get(b"content-disposition".as_slice())
                    .and_then(|v| v.first())
                    .map(|v| {
                        v.split_str(b";")
                            .next()
                            .unwrap_or(v)
                            .trim()
                            .to_ascii_lowercase()
                    });

                self.result.parts.push(EmlPart {
                    headers: self.map_to_proto_headers(&headers),
                    body: Some(body.to_vec()),
                    decoded_body: self.decode_body(&headers, body),
                    filename,
                    disposition,
                    ..Default::default()
                });
            }
            is_root = false;
        }

        Ok(mem::take(&mut self.result))
    }

    fn split_message<'a>(&self, input: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        if let Some(pos) = input.find("\r\n\r\n") {
            (&input[..pos], &input[pos + 4..])
        } else if let Some(pos) = input.find("\n\n") {
            (&input[..pos], &input[pos + 2..])
        } else {
            (input, &[][..])
        }
    }

    fn decode_body(
        &self,
        headers: &Headers,
        body: &[u8],
    ) -> Option<Vec<u8>> {
        let enc = headers.get(b"content-transfer-encoding".as_slice()).and_then(|v| v.first())?;
        match enc.to_ascii_lowercase().as_slice() {
            b"base64" => {
                let cleaned: Vec<u8> =
                    body.iter().filter(|&&b| !b.is_ascii_whitespace()).cloned().collect();
                BASE64_STANDARD.decode(cleaned).ok()
            }
            b"quoted-printable" => {
                quoted_printable::decode(body, quoted_printable::ParseMode::Robust).ok()
            }
            _ => None,
        }
    }

    fn map_to_proto_headers(
        &self,
        headers: &Headers,
    ) -> Vec<Header> {
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
    fn get_mime_param<'a>(header_value: &'a [u8], param_name: &[u8]) -> Option<&'a [u8]> {
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

    fn parse_headers(&self, headers_raw: &[u8]) -> Headers {
        let mut last_key: Option<Vec<u8>> = None;
        let mut headers = Headers::new();

        for line in headers_raw.lines() {
            #[allow(clippy::collapsible_if)]
            if line.starts_with(b" ") || line.starts_with(b"\t") {
                if let Some(k) = &last_key {
                    if let Some(values) = headers.get_mut(k.as_slice()) {
                        if let Some(last_val) = values.last_mut() {
                            last_val.push(b' ');
                            last_val.extend_from_slice(line.trim());
                        }
                    }
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
