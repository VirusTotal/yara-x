/*! Serializes Protocol Buffer (protobuf) messages into JSON format.

This crate provides functionality to serialize arbitrary protobuf messages
into a structured JSON representation. Special handling is applied to certain
protobuf field types that are not natively representable in JSON—most notably,
`bytes` fields.

Since raw byte sequences may contain non-UTF-8 data, they cannot be directly
encoded as JSON strings. Instead, they are serialized as an object whose only
key is `$bytes`, and whose value is a list with the base64-encoded bytes.
Timestamps are serialized in a similar way, using the `$timestamp` key. For
example:

```json
{
  "my_bytes_field": { "$bytes": ["dGhpcyBpcyB0aGUgb3JpZ2luYWwgdmFsdWU="] },
  "my_timestamp_field": { "$timestamp": [1748591440] }
}
```

No message or map can produce an object like these. Protobuf field names
can't start with `$`, and map values can't be repeated fields, so they are
never serialized as JSON arrays. This means that the JSON can be decoded
back without mistaking a map for an encoded value.

This is the [`Format::Default`] format. The `yr dump` command uses
[`Format::YrDump`] instead, which keeps the format it has always produced:

```json
{
  "my_bytes_field": {
    "encoding": "base64",
    "value": "dGhpcyBpcyB0aGUgb3JpZ2luYWwgdmFsdWU="
  },
  "my_timestamp_field": {
    "encoding": "timestamp",
    "value": 1748591440
  }
}
```

In this format a `map<string, string>` with `encoding` and `value` keys is
indistinguishable from an encoded value, so it shouldn't be used for JSON
that is decoded back.
*/

use std::borrow::Cow;
use std::cmp::Ordering;
use std::io::{Error, Write};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use itertools::Itertools;
use protobuf::MessageDyn;
use protobuf::reflect::ReflectFieldRef::{Map, Optional, Repeated};
use protobuf::reflect::{FieldDescriptor, MessageRef, ReflectValueRef};
use yansi::{Color, Paint, Style};

use crate::{FieldFormat, get_field_format};

const INDENTATION: u16 = 4;

// A struct that represents colors for output
#[derive(Default)]
struct Colors {
    string: Style,
    field_name: Style,
}

/// Formats in which [`Serializer`] can write `bytes` and timestamp values.
///
/// See the [module documentation](self) for details.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `{ "$bytes": ["..."] }` for bytes, and `{ "$timestamp": [...] }` for
    /// timestamps.
    #[default]
    Default,
    /// `{ "encoding": "base64", "value": "..." }` for bytes, and
    /// `{ "encoding": "timestamp", "value": ... }` for timestamps. Used only
    /// by `yr dump`, for backward compatibility.
    YrDump,
}

/// Serializes a protobuf to JSON format.
///
/// Takes a protobuf message and produces a JSON representation of it.
pub struct Serializer<W: Write> {
    indent: u16,
    output: W,
    colors: Colors,
    format: Format,
}

impl<W: Write> Serializer<W> {
    /// Creates a new YAML serializer that writes its output to `w`.
    pub fn new(w: W) -> Self {
        Self {
            output: w,
            indent: 0,
            colors: Colors::default(),
            format: Format::default(),
        }
    }

    /// Specifies the format used for `bytes` and timestamp values.
    ///
    /// The default setting is [`Format::Default`].
    pub fn with_format(&mut self, format: Format) -> &mut Self {
        self.format = format;
        self
    }

    /// Specifies whether the serializer should colorize the output.
    ///
    /// If true, the output contain ANSI escape sequences that make it
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn with_colors(&mut self, yes: bool) -> &mut Self {
        self.colors = if yes {
            Colors {
                string: Color::Green.foreground(),
                field_name: Color::Yellow.foreground(),
            }
        } else {
            Colors::default()
        };
        self
    }

    /// Serializes the given protobuf message.
    pub fn serialize(&mut self, msg: &dyn MessageDyn) -> Result<(), Error> {
        self.write_msg(&MessageRef::new(msg))
    }
}

impl<W: Write> Serializer<W> {
    fn print_integer_value<T: Into<i64> + ToString + Copy>(
        &mut self,
        value: T,
        format: FieldFormat,
    ) -> Result<(), std::io::Error> {
        if matches!(format, FieldFormat::Timestamp) {
            match self.format {
                Format::Default => write!(
                    self.output,
                    "{{ \"$timestamp\": [{}] }}",
                    value.to_string()
                ),
                Format::YrDump => write!(
                    self.output,
                    "{{ \"encoding\": \"timestamp\", \"value\": {} }}",
                    value.to_string()
                ),
            }
        } else {
            write!(self.output, "{}", value.to_string())
        }
    }

    fn escape(s: &str) -> Cow<'_, str> {
        if s.chars().any(|c| {
            // C0 controls (U+0000–U+001F: NUL–US), including \n, \r, \t
            // all must be escaped per RFC 8259 §7.
            c.is_ascii_control() || matches!(c, '"' | '\\')
        }) {
            let mut result = String::with_capacity(s.len());
            for c in s.chars() {
                match c {
                    '\n' => result.push_str(r"\n"),
                    '\r' => result.push_str(r"\r"),
                    '\t' => result.push_str(r"\t"),
                    '"' => result.push_str("\\\""),
                    '\\' => result.push_str(r"\\"),
                    c if c.is_ascii_control() => {
                        // Remaining C0 controls (U+0000–U+001F: NUL–US) not
                        // covered by the arms above.
                        // RFC 8259 §7 requires \uXXXX escaping.
                        result.push_str(&format!(r"\u{:04x}", c as u32));
                    }
                    _ => result.push(c),
                }
            }
            Cow::Owned(result)
        } else {
            Cow::Borrowed(s)
        }
    }

    fn write_field_name(&mut self, name: &str) -> Result<(), Error> {
        write!(self.output, "\"{}\": ", name.paint(self.colors.field_name))
    }

    fn write_msg(&mut self, msg: &MessageRef) -> Result<(), Error> {
        let descriptor = msg.descriptor_dyn();

        // Iterator that returns only the non-empty fields in the message.
        let mut non_empty_fields = descriptor
            .fields()
            .filter(|field| match field.get_reflect(&**msg) {
                Optional(optional) => optional.value().is_some(),
                Repeated(repeated) => !repeated.is_empty(),
                Map(map) => !map.is_empty(),
            })
            .peekable();

        write!(self.output, "{{")?;
        self.indent += INDENTATION;
        self.newline()?;

        while let Some(field) = non_empty_fields.next() {
            match field.get_reflect(&**msg) {
                Optional(optional) => {
                    let value = optional.value().unwrap();
                    self.write_field_name(field.name())?;
                    self.write_value(&field, &value)?;
                }
                Repeated(repeated) => {
                    self.write_field_name(field.name())?;
                    write!(self.output, "[")?;
                    self.indent += INDENTATION;
                    self.newline()?;
                    let mut items = repeated.into_iter().peekable();
                    while let Some(value) = items.next() {
                        self.write_value(&field, &value)?;
                        if items.peek().is_some() {
                            write!(self.output, ",")?;
                            self.newline()?;
                        }
                    }
                    self.indent -= INDENTATION;
                    self.newline()?;
                    write!(self.output, "]")?;
                }
                Map(map) => {
                    self.write_field_name(field.name())?;
                    write!(self.output, "{{")?;
                    self.indent += INDENTATION;
                    self.newline()?;

                    // Iteration order is not stable (i.e: the order in which
                    // items are returned can vary from one execution to the
                    // other), because the underlying data structure is a
                    // HashMap. For this reason items are wrapped in a KV
                    // struct (which implement the Ord trait) and sorted.
                    // Key-value pairs are sorted by key.
                    let mut items = map
                        .into_iter()
                        .map(|(key, value)| KV { key, value })
                        .sorted()
                        .peekable();

                    while let Some(item) = items.next() {
                        let key = item.key.to_string();
                        write!(
                            self.output,
                            "\"{}\": ",
                            Self::escape(&key).paint(self.colors.string)
                        )?;
                        self.write_value(&field, &item.value)?;
                        if items.peek().is_some() {
                            write!(self.output, ",")?;
                            self.newline()?;
                        } else {
                            self.indent -= INDENTATION;
                            self.newline()?;
                        }
                    }
                    write!(self.output, "}}")?;
                }
            }

            if non_empty_fields.peek().is_some() {
                write!(self.output, ",")?;
                self.newline()?;
            }
        }

        self.indent -= INDENTATION;
        self.newline()?;
        write!(self.output, "}}")?;

        Ok(())
    }

    fn write_value(
        &mut self,
        field: &FieldDescriptor,
        value: &ReflectValueRef,
    ) -> Result<(), Error> {
        match value {
            ReflectValueRef::U32(v) => {
                self.print_integer_value(*v, get_field_format(field))?
            }
            ReflectValueRef::U64(v) => {
                self.print_integer_value(*v as i64, get_field_format(field))?
            }
            ReflectValueRef::I32(v) => {
                self.print_integer_value(*v, get_field_format(field))?
            }
            ReflectValueRef::I64(v) => {
                self.print_integer_value(*v, get_field_format(field))?
            }
            ReflectValueRef::F32(v) => write!(self.output, "{v}")?,
            ReflectValueRef::F64(v) => write!(self.output, "{v}")?,
            ReflectValueRef::Bool(v) => write!(self.output, "{v}")?,
            ReflectValueRef::String(v) => {
                write!(
                    self.output,
                    "\"{}\"",
                    Self::escape(v).paint(self.colors.string)
                )?;
            }
            ReflectValueRef::Bytes(v) => {
                let encoded = BASE64_STANDARD.encode(v);
                let encoded = encoded.paint(self.colors.string);
                match self.format {
                    Format::Default => write!(
                        self.output,
                        "{{ \"$bytes\": [\"{}\"] }}",
                        encoded
                    )?,
                    Format::YrDump => write!(
                        self.output,
                        "{{ \"encoding\": \"base64\", \"value\": \"{}\"}}",
                        encoded
                    )?,
                }
            }
            ReflectValueRef::Enum(d, v) => match d.value_by_number(*v) {
                Some(e) => write!(self.output, "\"{}\"", e.name())?,
                None => write!(self.output, "{v}")?,
            },
            ReflectValueRef::Message(msg) => self.write_msg(msg)?,
        }
        Ok(())
    }

    fn newline(&mut self) -> Result<(), Error> {
        writeln!(self.output)?;
        for _ in 0..self.indent {
            write!(self.output, " ")?;
        }
        Ok(())
    }
}

/// Helper type that allows to sort the entries in protobuf map.
struct KV<'a> {
    key: ReflectValueRef<'a>,
    value: ReflectValueRef<'a>,
}

impl PartialOrd for KV<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KV<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.key {
            ReflectValueRef::U32(v) => {
                v.cmp(&other.key.to_u32().unwrap_or_default())
            }
            ReflectValueRef::U64(v) => {
                v.cmp(&other.key.to_u64().unwrap_or_default())
            }
            ReflectValueRef::I32(v) => {
                v.cmp(&other.key.to_i32().unwrap_or_default())
            }
            ReflectValueRef::I64(v) => {
                v.cmp(&other.key.to_i64().unwrap_or_default())
            }
            ReflectValueRef::Bool(v) => {
                v.cmp(&other.key.to_bool().unwrap_or_default())
            }
            ReflectValueRef::String(v) => {
                v.cmp(other.key.to_str().unwrap_or_default())
            }
            _ => {
                // Protobuf doesn't support map keys of any other type
                // except the ones listed above.
                panic!("unsupported type in map key")
            }
        }
    }
}

impl PartialEq for KV<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.key.to_str().eq(&other.key.to_str())
    }
}

impl Eq for KV<'_> {}
