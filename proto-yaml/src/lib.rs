/*! Serializes a Protocol Buffer (protobuf) message to YAML.

This crates serializes arbitrary protobuf messages to YAML format, producing
YAML that is user-friendly, customizable and colorful. Some aspects of the
produced YAML can be customized by using specific options in your `.proto`
files. Let's use the following protobuf message definition as an example:

```protobuf
import "yaml.proto";

message MyMessage {
  optional int32 some_field = 1 [(yaml.field).fmt = "x"];
}
```

The first think to note is the `import "yaml.proto"` statement before the
message definition. The `yaml.proto` file defines the existing YAML formatting
options, so you must include it in your own `.proto` file in order to be able
to use the such options.

The `[(yaml.field).fmt = "x"]` modifier, when applied to some field, indicates
that values of that field must be rendered in hexadecimal form. The list of
supported format modifiers is:

- `x`: Serializes the value an hexadecimal number. Only valid for integer
       fields.
- `t`: Serializes the field as a timestamp. The value itself is rendered as a
       decimal integer, but a comment is added with the timestamp in a
       human-friendly format. Only valid for integer fields.

# Examples

Protobuf definition:

```protobuf
import "yaml.proto";

message MyMessage {
  optional int32 some_field = 1 [(yaml.field).fmt = "x"];
  optional int64 some_timestamp = 2 [(yaml.field).fmt = "t"];
}
```

YAML output:

```yaml
some_field: 0x8b1;
timestamp: 999999999 # 2001-09-09 01:46:39 UTC
```
 */

use chrono::prelude::DateTime;
use itertools::Itertools;
use protobuf::MessageDyn;
use std::cmp::Ordering;
use std::io::{Error, Write};
use yansi::{Color, Paint, Style};

use protobuf::descriptor::FieldDescriptorProto;
use protobuf::reflect::ReflectFieldRef::{Map, Optional, Repeated};
use protobuf::reflect::ReflectValueRef;
use protobuf::reflect::{FieldDescriptor, MessageRef};

use crate::yaml::exts::field as field_options;

#[cfg(test)]
mod tests;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

const INDENTATION: u16 = 4;

// A struct that represents colors for output
#[derive(Default)]
struct Colors {
    string: Style,
    field_name: Style,
    repeated_name: Style,
    comment: Style,
}

/// A struct that represents options for a field values
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
                repeated_name: Color::Yellow.foreground(),
                comment: Color::Rgb(222, 184, 135).foreground(),
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
    fn get_value_options(
        &mut self,
        field_descriptor: &FieldDescriptorProto,
    ) -> ValueOptions {
        field_options
            .get(&field_descriptor.options)
            .map(|options| ValueOptions {
                // Default for boolean is false
                is_hex: options.fmt() == "x",
                is_timestamp: options.fmt() == "t",
            })
            .unwrap_or_default()
    }

    fn print_integer_value_with_options<T: Into<i64> + ToString + Copy>(
        &mut self,
        value: T,
        value_options: &ValueOptions,
    ) -> Result<(), std::io::Error> {
        if value_options.is_hex {
            write!(self.output, "0x{:x}", value.into())?;
        } else if value_options.is_timestamp {
            let timestamp =
                DateTime::from_timestamp(value.into(), 0).unwrap().to_string();

            write!(self.output, "{} ", value.to_string())?;
            self.write_comment(&timestamp)?;
        } else {
            write!(self.output, "{}", value.to_string())?;
        };

        Ok(())
    }

    fn quote_bytes(&mut self, bytes: &[u8]) -> String {
        let mut result = String::new();
        result.push('"');
        for b in bytes.iter() {
            match b {
                b'\n' => result.push_str(r"\n"),
                b'\r' => result.push_str(r"\r"),
                b'\t' => result.push_str(r"\t"),
                b'\'' => result.push_str("\\\'"),
                b'"' => result.push_str("\\\""),
                b'\\' => result.push_str(r"\\"),
                b'\x20'..=b'\x7e' => result.push(*b as char),
                _ => {
                    result.push_str(&format!("\\x{:02x}", *b));
                }
            }
        }
        result.push('"');
        result
    }

    fn quote_str(&mut self, s: &str) -> String {
        let mut result = String::new();
        result.push('"');
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
        result.push('"');
        result
    }

    fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let comment = format!("# {}", comment);
        write!(self.output, "{}", comment.paint(self.colors.comment))
    }

    fn write_field_name(&mut self, name: &str) -> Result<(), Error> {
        write!(self.output, "{}:", name.paint(self.colors.field_name))
    }

    fn write_repeated_name(&mut self, name: &str) -> Result<(), Error> {
        write!(self.output, "{}:", name.paint(self.colors.repeated_name))
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
                            "-".paint(self.colors.repeated_name)
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
                let quoted = self.quote_str(v);
                write!(self.output, "{}", quoted.paint(self.colors.string))?;
            }
            ReflectValueRef::Bytes(v) => {
                let quoted = self.quote_bytes(v);
                write!(self.output, "{}", quoted.paint(self.colors.string))?;
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
