use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use itertools::Itertools;
use protobuf::MessageDyn;
use protobuf_support::text_format::escape_bytes_to;
use std::cmp::Ordering;
use std::io::{Error, Write};
use yansi::Color;
use yansi::Paint;

use protobuf::descriptor::FieldDescriptorProto;
use protobuf::reflect::ReflectFieldRef::{Map, Optional, Repeated};
use protobuf::reflect::ReflectValueRef;
use protobuf::reflect::{FieldDescriptor, MessageRef};

use crate::yaml::exts::field_options;

#[cfg(test)]
mod tests;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

const INDENTATION: u16 = 4;

// A struct that represents colors for output
struct ColorsConfig;

impl ColorsConfig {
    const STRING: Color = Color::Green;
    const FIELD_NAME: Color = Color::Blue;
    const REPEATED_NAME: Color = Color::Yellow;
    const COMMENT: Color = Color::RGB(222, 184, 135); // Brown
}

// A struct that represents options for a field values
#[derive(Debug, Default, Clone)]
struct ValueOptions {
    is_hex: bool,
    is_timestamp: bool,
}

/// Serializes a protobuf to YAML format.
///
/// Takes a protobuf message and produces a YAML representation of it. The
/// produced YAML intends to be as human-friendly as possible, by including
/// comments that clarify the meaning of certain values, like timestamps.
pub struct Serializer<W: Write> {
    indent: u16,
    output: W,
}

impl<W: Write> Serializer<W> {
    /// Creates a new YAML serializer that writes its output to `w`.
    pub fn new(w: W) -> Self {
        Self { output: w, indent: 0 }
    }

    /// Serializes the given protobuf message.
    pub fn serialize(&mut self, msg: &dyn MessageDyn) -> Result<(), Error> {
        self.write_msg(&MessageRef::new(msg))
    }
}

impl<W: Write> Serializer<W> {
    fn get_value_options(
        &mut self,
        field_descriptor: &FieldDescriptorProto,
    ) -> ValueOptions {
        field_options
            .get(&field_descriptor.options)
            .map(|options| ValueOptions {
                // Default for boolean is false
                is_hex: options.yaml_fmt() == "x",
                is_timestamp: options.yaml_fmt() == "t",
            })
            .unwrap_or_default()
    }

    fn print_integer_value_with_options<T: Into<i64> + ToString + Copy>(
        &mut self,
        value: T,
        value_options: &ValueOptions,
    ) -> Result<(), std::io::Error> {
        let field_value = if value_options.is_hex {
            format!("0x{:x}", value.into())
        } else if value_options.is_timestamp {
            let timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDateTime::from_timestamp_opt(value.into(), 0).unwrap(),
                Utc,
            );
            format!(
                "{} {}",
                value.to_string(),
                self.write_as_a_comment(timestamp.to_string())
            )
        } else {
            value.to_string()
        };
        write!(self.output, "{}", field_value)
    }

    fn quote_bytes(&mut self, bytes: &[u8]) -> String {
        let mut result = String::new();
        result.push('"');
        escape_bytes_to(bytes, &mut result);
        result.push('"');
        result
    }

    fn write_as_a_comment(&mut self, value: String) -> Paint<String> {
        ColorsConfig::COMMENT.paint(format!("{} {}", "#", value))
    }

    fn write_field_name(&mut self, name: &str) -> Result<(), Error> {
        write!(self.output, "{}:", ColorsConfig::FIELD_NAME.paint(name).bold())
    }

    fn write_repeated_name(&mut self, name: &str) -> Result<(), Error> {
        write!(
            self.output,
            "{}:",
            ColorsConfig::REPEATED_NAME.paint(name).bold()
        )
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

        while let Some(field) = non_empty_fields.next() {
            match field.get_reflect(&**msg) {
                Optional(optional) => {
                    let value = optional.value().unwrap();
                    self.write_field_name(field.name())?;
                    self.indent += INDENTATION;
                    self.write_name_value_separator(&value)?;
                    self.write_value(&field, &value)?;
                    self.indent -= INDENTATION;
                }
                Repeated(repeated) => {
                    self.write_repeated_name(field.name())?;
                    self.newline()?;
                    let mut items = repeated.into_iter().peekable();
                    while let Some(value) = items.next() {
                        write!(
                            self.output,
                            "{}{} ",
                            " ".repeat((INDENTATION - 2) as usize),
                            ColorsConfig::REPEATED_NAME.paint("-").bold()
                        )?;
                        self.indent += INDENTATION;
                        self.write_value(&field, &value)?;
                        self.indent -= INDENTATION;
                        if items.peek().is_some() {
                            self.newline()?;
                        }
                    }
                }
                Map(map) => {
                    self.write_field_name(field.name())?;
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
                        // We have to escape possible \n in key as it is interpreted as string
                        // it is covered in tests
                        let escaped_key =
                            self.quote_bytes(item.key.to_string().as_bytes());
                        self.write_field_name(escaped_key.as_str())?;
                        self.indent += INDENTATION;
                        self.write_name_value_separator(&item.value)?;
                        self.write_value(&field, &item.value)?;
                        self.indent -= INDENTATION;
                        if items.peek().is_some() {
                            self.newline()?;
                        }
                    }
                    self.indent -= INDENTATION;
                }
            }

            if non_empty_fields.peek().is_some() {
                self.newline()?;
            }
        }

        Ok(())
    }

    fn write_value(
        &mut self,
        field_descriptor: &FieldDescriptor,
        value: &ReflectValueRef,
    ) -> Result<(), Error> {
        let value_options = self.get_value_options(field_descriptor.proto());
        match value {
            ReflectValueRef::U32(v) => {
                self.print_integer_value_with_options(*v, &value_options)?
            }
            ReflectValueRef::U64(v) => self
                .print_integer_value_with_options(*v as i64, &value_options)?,
            ReflectValueRef::I32(v) => {
                self.print_integer_value_with_options(*v, &value_options)?
            }
            ReflectValueRef::I64(v) => {
                self.print_integer_value_with_options(*v, &value_options)?
            }
            ReflectValueRef::F32(v) => write!(self.output, "{:.1}", v)?,
            ReflectValueRef::F64(v) => write!(self.output, "{:.1}", v)?,
            ReflectValueRef::Bool(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::String(v) => {
                let quoted_string = self.quote_bytes(v.as_bytes());
                write!(
                    self.output,
                    "{}",
                    ColorsConfig::STRING.paint(&quoted_string)
                )?;
            }
            ReflectValueRef::Bytes(v) => {
                let quoted_string = self.quote_bytes(v);
                write!(
                    self.output,
                    "{}",
                    ColorsConfig::STRING.paint(&quoted_string)
                )?;
            }
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

    fn write_name_value_separator(
        &mut self,
        value: &ReflectValueRef,
    ) -> Result<(), Error> {
        if let ReflectValueRef::Message(_) = value {
            self.newline()?
        } else {
            write!(self.output, " ")?
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
