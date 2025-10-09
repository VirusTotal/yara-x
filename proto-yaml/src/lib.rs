/*! Serializes a Protocol Buffer (protobuf) message to YAML.

This crate serializes arbitrary protobuf messages to YAML format, producing
YAML that is user-friendly, customizable and colorful. Some aspects of the
produced YAML can be customized by using specific options in your `.proto`
files. Let's use the following protobuf message definition as an example:

```protobuf
import "yara.proto";

message MyMessage {
  optional int32 some_field = 1 [(yara.field_options).fmt = "x"];
}
```

The first think to note is the `import "yara.proto"` statement before the
message definition. The `yara.proto` file defines the existing formatting
options, so you must include it in your own `.proto` file in order to be able
to use the such options.

The `[(yara.field_options).fmt = "x"]` modifier, when applied to some field,
indicates that values of that field must be rendered in hexadecimal form. The
list of supported format modifiers is:

- `x`: Serializes the value as a hexadecimal number. Only valid for integer
  fields.

- `t`: Serializes the field as a timestamp. The value itself is rendered as a
  decimal integer, but a comment is added with the timestamp in a human-friendly
  format. Only valid for integer fields.

- `flag:ENUM_TYPE_NAME`: Serializes the field as a set of flags. The value
  is rendered as a hexadecimal number, but a comment is added with the names
  of the flags that are enabled. `ENUM_TYPE_NAME` must be the name of enum
  where each value represents a flag.

# Examples

Protobuf definition:

```protobuf
import "yara.proto";

message MyMessage {
  optional int32 some_field = 1 [(yara.field_options).fmt = "x"];
  optional int64 some_timestamp = 2 [(yara.field_options).fmt = "t"];
  optional int32 some_flag = 3 [(yara.field_options).fmt = "flags:MyFlags"];
}

enum MyFlags {
    FOO = 0x01;
    BAR = 0x02;
    BAZ = 0x04;
}
```

YAML output:

```yaml
some_field: 0x8b1;
some_timestamp: 999999999  # 2001-09-09 01:46:39 UTC
some_flag: 0x06  # BAR | BAZ
```
 */

use std::borrow::Cow;
use std::cmp::Ordering;
use std::io::{Error, Write};
use std::ops::BitAnd;

use chrono::prelude::DateTime;
use itertools::Itertools;
use protobuf::reflect::ReflectFieldRef::{Map, Optional, Repeated};
use protobuf::reflect::{FieldDescriptor, MessageRef, ReflectValueRef};
use protobuf::MessageDyn;
use yansi::{Color, Paint, Style};

use yara_x_proto::{get_field_format, FieldFormat};

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
    fn print_integer_value<T: Into<i64> + ToString + Copy>(
        &mut self,
        value: T,
        format: FieldFormat,
    ) -> Result<(), std::io::Error> {
        match format {
            FieldFormat::Flags(flags_enum) => {
                let value = value.into();
                write!(self.output, "0x{value:x}")?;
                let mut f = vec![];
                for v in flags_enum.values() {
                    if value.bitand(v.value() as i64) != 0 {
                        f.push(v.name().to_string());
                    }
                }
                if !f.is_empty() {
                    self.write_comment(f.into_iter().join(" | ").as_str())?;
                }
            }
            FieldFormat::Hex => {
                write!(self.output, "0x{:x}", value.into())?;
            }
            FieldFormat::Timestamp => {
                write!(self.output, "{}", value.to_string())?;
                self.write_comment(
                    DateTime::from_timestamp(value.into(), 0)
                        .unwrap()
                        .to_string()
                        .as_str(),
                )?;
            }
            _ => {
                write!(self.output, "{}", value.to_string())?;
            }
        }

        Ok(())
    }

    fn escape_bytes(bytes: &[u8]) -> String {
        let mut result = String::with_capacity(bytes.len());
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
        result
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

    fn write_comment(&mut self, comment: &str) -> Result<(), Error> {
        let comment = format!("  # {comment}");
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
                        let key = format!("{}", item.key);
                        let escaped_key = Self::escape(&key);
                        write!(
                            self.output,
                            "\"{}\":",
                            escaped_key.paint(self.colors.field_name)
                        )?;
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
            ReflectValueRef::F32(v) => write!(self.output, "{v:.1}")?,
            ReflectValueRef::F64(v) => write!(self.output, "{v:.1}")?,
            ReflectValueRef::Bool(v) => write!(self.output, "{v}")?,
            ReflectValueRef::String(v) => {
                write!(
                    self.output,
                    "\"{}\"",
                    Self::escape(v).paint(self.colors.string)
                )?;
            }
            ReflectValueRef::Bytes(v) => {
                write!(
                    self.output,
                    "\"{}\"",
                    Self::escape_bytes(v).paint(self.colors.string)
                )?;
            }
            ReflectValueRef::Enum(d, v) => match d.value_by_number(*v) {
                Some(e) => write!(self.output, "{}", e.name())?,
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
