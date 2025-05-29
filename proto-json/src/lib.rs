/*! Serializes Protocol Buffer (protobuf) messages into JSON format.

This crate provides functionality to serialize arbitrary protobuf messages
into a structured JSON representation. Special handling is applied to certain
protobuf field types that are not natively representable in JSON—most notably,
`bytes` fields.

Since raw byte sequences may contain non-UTF-8 data, they cannot be directly
encoded as JSON strings. Instead, they are serialized as an object containing
the base64-encoded value along with an encoding identifier. For example:

```json
{
  "my_bytes_field": {
    "encoding": "base64",
    "value": "dGhpcyBpcyB0aGUgb3JpZ2luYWwgdmFsdWU="
  }
}
```
*/

use std::borrow::Cow;
use std::cmp::Ordering;
use std::io::{Error, Write};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use itertools::Itertools;
use protobuf::reflect::ReflectFieldRef::{Map, Optional, Repeated};
use protobuf::reflect::{MessageRef, ReflectValueRef};
use protobuf::MessageDyn;
use yansi::{Color, Paint, Style};

#[cfg(test)]
mod tests;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

const INDENTATION: u16 = 4;

// A struct that represents colors for output
#[derive(Default)]
struct Colors {
    string: Style,
    field_name: Style,
}

/// Serializes a protobuf to JSON format.
///
/// Takes a protobuf message and produces a JSON representation of it.
pub struct Serializer<W: Write> {
    indent: u16,
    output: W,
    colors: Colors,
}

impl<W: Write> Serializer<W> {
    /// Creates a new YAML serializer that writes its output to `w`.
    pub fn new(w: W) -> Self {
        Self { output: w, indent: 0, colors: Colors::default() }
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
    ) -> Result<(), std::io::Error> {
        write!(self.output, "{}", value.to_string())
    }

    fn escape(s: &str) -> Cow<'_, str> {
        if s.chars()
            .any(|c| matches!(c, '\n' | '\r' | '\t' | '\'' | '"' | '\\'))
        {
            let mut result = String::with_capacity(s.len());
            for c in s.chars() {
                match c {
                    '\n' => result.push_str(r"\n"),
                    '\r' => result.push_str(r"\r"),
                    '\t' => result.push_str(r"\t"),
                    '\'' => result.push_str("\\\'"),
                    '"' => result.push_str("\\\""),
                    '\\' => result.push_str(r"\\"),
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
                    self.write_value(&value)?;
                }
                Repeated(repeated) => {
                    self.write_field_name(field.name())?;
                    write!(self.output, "[")?;
                    self.indent += INDENTATION;
                    self.newline()?;
                    let mut items = repeated.into_iter().peekable();
                    while let Some(value) = items.next() {
                        self.write_value(&value)?;
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
                        self.write_value(&item.value)?;
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

    fn write_value(&mut self, value: &ReflectValueRef) -> Result<(), Error> {
        match value {
            ReflectValueRef::U32(v) => self.print_integer_value(*v)?,
            ReflectValueRef::U64(v) => self.print_integer_value(*v as i64)?,
            ReflectValueRef::I32(v) => self.print_integer_value(*v)?,
            ReflectValueRef::I64(v) => self.print_integer_value(*v)?,
            ReflectValueRef::F32(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::F64(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::Bool(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::String(v) => {
                write!(
                    self.output,
                    "\"{}\"",
                    Self::escape(v).paint(self.colors.string)
                )?;
            }
            ReflectValueRef::Bytes(v) => write!(
                self.output,
                "{{ \"encoding\": \"base64\", \"value\": \"{}\"}}",
                BASE64_STANDARD.encode(v).paint(self.colors.string)
            )?,
            ReflectValueRef::Enum(d, v) => match d.value_by_number(*v) {
                Some(e) => write!(self.output, "{}", e.name())?,
                None => write!(self.output, "{}", v)?,
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
