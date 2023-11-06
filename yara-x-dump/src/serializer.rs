use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use protobuf::descriptor::FieldDescriptorProto;
use protobuf::reflect::MessageRef;
use protobuf::reflect::ReflectFieldRef;
use protobuf::reflect::ReflectValueRef;
use protobuf_support::text_format::quote_bytes_to;
use std::fmt::Write;
use yansi::Color;
use yara_x_proto::exts::field_options;

use crate::Error;

// A struct that represents serializers
struct JsonSerializer;
struct YamlSerializer;
struct TomlSerializer;
struct XmlSerializer;

struct Colors;

impl Colors {
    const GREEN: Color = Color::RGB(51, 255, 153);
    const BLUE: Color = Color::RGB(51, 51, 255);
    const YELLOW: Color = Color::RGB(255, 255, 102);
}

#[derive(Debug, Default, Clone)]
struct ValueOptions {
    is_hex: bool,
    is_timestamp: bool,
}

/// A trait for any type that can serialize a message
pub(crate) trait Serializer {
    fn serialize(&self, message: &str) -> Result<String, Error>;
}

/// Implement the trait for the JSON serializer
impl Serializer for JsonSerializer {
    fn serialize(&self, message: &str) -> Result<String, Error> {
        let value = serde_json::from_str::<serde_json::Value>(message)?;
        Ok(serde_json::to_string_pretty(&value)?)
    }
}

/// Implement the trait for the YAML serializer
impl Serializer for YamlSerializer {
    fn serialize(&self, message: &str) -> Result<String, Error> {
        let value = serde_json::from_str::<serde_yaml::Value>(message)?;
        Ok(serde_yaml::to_string(&value)?)
    }
}

/// Implement the trait for the TOML serializer
impl Serializer for TomlSerializer {
    fn serialize(&self, message: &str) -> Result<String, Error> {
        let value = serde_json::from_str::<toml::Value>(message)?;
        Ok(toml::to_string_pretty(&value)?)
    }
}

/// Implement the trait for the XML serializer
impl Serializer for XmlSerializer {
    fn serialize(&self, message: &str) -> Result<String, Error> {
        // Create a new XML builder and get the XML
        let mut xml_builder = xml2json_rs::XmlConfig::new()
            .rendering(xml2json_rs::Indentation::new(b' ', 2))
            .decl(xml2json_rs::Declaration::new(
                xml2json_rs::Version::XML10,
                Some(xml2json_rs::Encoding::UTF8),
                Some(true),
            ))
            .root_name("file")
            .finalize();
        let xml = xml_builder.build_from_json_string(message)?;
        Ok(xml)
    }
}

/// A function that returns a trait object based on the format
pub(crate) fn get_serializer(
    format: &str,
) -> Result<Box<dyn Serializer>, Error> {
    match format {
        // Return a JSON serializer
        "json" => Ok(Box::new(JsonSerializer)),
        // Return a YAML serializer
        "yaml" => Ok(Box::new(YamlSerializer)),
        // Return a TOML serializer
        "toml" => Ok(Box::new(TomlSerializer)),
        // Return an XML serializer
        "xml" => Ok(Box::new(XmlSerializer)),
        // Return an error if the format is unsupported
        _ => Err(Error::UnsupportedFormat),
    }
}

// Print a field name with correct indentation
fn print_field_name(
    buf: &mut String,
    field_name: &str,
    indent: usize,
    is_first_line: &mut bool,
) -> Result<(), Error> {
    let mut indentation = get_indentation(indent);

    if !field_name.is_empty() {
        if *is_first_line {
            if !indentation.is_empty() {
                indentation.pop();
                indentation.pop();
            }
            write!(
                buf,
                "{}{} {}: ",
                indentation,
                Colors::YELLOW.paint("-").bold(),
                Colors::BLUE.paint(field_name)
            )?;
            *is_first_line = false;
        } else {
            write!(
                buf,
                "{}{}: ",
                indentation,
                Colors::BLUE.paint(field_name)
            )?;
        }
    }
    Ok(())
}

// Print a field value with correct indentation for multiple value formats
fn print_field_value(
    buf: &mut String,
    value: ReflectValueRef,
    value_options: &ValueOptions,
    indent: usize,
    is_first_line: &mut bool,
) -> Result<(), Error> {
    match value {
        ReflectValueRef::Message(m) => {
            *is_first_line = true;
            get_human_readable_output(&m, buf, indent + 1, is_first_line)?;
        }
        ReflectValueRef::Enum(d, v) => match d.value_by_number(v) {
            Some(e) => writeln!(buf, "{}", e.name())?,
            None => writeln!(buf, "{}", v)?,
        },
        ReflectValueRef::String(s) => {
            quote_bytes_to(s.as_bytes(), buf);
            buf.push('\n');
        }
        ReflectValueRef::Bytes(b) => {
            quote_bytes_to(b, buf);
            buf.push('\n');
        }
        ReflectValueRef::I32(v) => {
            let field_value = if value_options.is_hex {
                format!("{} (0x{:x})", v, v)
            } else if value_options.is_timestamp {
                format!(
                    "{} ({})",
                    v,
                    DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(v as i64, 0)
                            .unwrap(),
                        Utc,
                    )
                )
            } else {
                v.to_string()
            };
            writeln!(buf, "{}", field_value)?;
        }
        ReflectValueRef::I64(v) => {
            let field_value = if value_options.is_hex {
                format!("{} (0x{:x})", v, v)
            } else if value_options.is_timestamp {
                format!(
                    "{} ({})",
                    v,
                    DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(v, 0).unwrap(),
                        Utc,
                    )
                )
            } else {
                v.to_string()
            };
            writeln!(buf, "{}", field_value)?;
        }
        ReflectValueRef::U32(v) => {
            let field_value = if value_options.is_hex {
                format!("{} (0x{:x})", v, v)
            } else if value_options.is_timestamp {
                format!(
                    "{} ({})",
                    v,
                    DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(v as i64, 0)
                            .unwrap(),
                        Utc,
                    )
                )
            } else {
                v.to_string()
            };
            writeln!(buf, "{}", field_value)?;
        }
        ReflectValueRef::U64(v) => {
            let field_value = if value_options.is_hex {
                format!("{} (0x{:x})", v, v)
            } else if value_options.is_timestamp {
                format!(
                    "{} ({})",
                    v,
                    DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(v as i64, 0)
                            .unwrap(),
                        Utc,
                    )
                )
            } else {
                v.to_string()
            };
            writeln!(buf, "{}", field_value)?;
        }
        ReflectValueRef::Bool(v) => {
            writeln!(buf, "{}", v)?;
        }
        ReflectValueRef::F32(v) => {
            writeln!(buf, "{:.1}", v)?;
        }
        ReflectValueRef::F64(v) => {
            writeln!(buf, "{:.1}", v)?;
        }
    }
    Ok(())
}

// Get the value options for a field
fn get_value_options(field_descriptor: &FieldDescriptorProto) -> ValueOptions {
    field_options
        .get(&field_descriptor.options)
        .map(|options| ValueOptions {
            // Default for boolean is false
            is_hex: options.hex_value.unwrap_or_default(),
            is_timestamp: options.timestamp.unwrap_or_default(),
        })
        .unwrap_or_default()
}

// Print a field name and value
fn print_field(
    buf: &mut String,
    field_name: &str,
    value: ReflectValueRef,
    field_descriptor: &FieldDescriptorProto,
    indent: usize,
    is_first_line: &mut bool,
) -> Result<(), Error> {
    let value_options = get_value_options(field_descriptor);

    print_field_name(buf, field_name, indent, is_first_line)?;
    print_field_value(buf, value, &value_options, indent, is_first_line)?;
    Ok(())
}

// Get indentation level
fn get_indentation(indent: usize) -> String {
    "    ".repeat(indent)
}

/// A function that returns a human-readable output
pub fn get_human_readable_output(
    msg: &MessageRef,
    buf: &mut String,
    indent: usize,
    first_line: &mut bool,
) -> Result<(), Error> {
    let desc = msg.descriptor_dyn();

    // Iterate over the fields of the message
    for f in desc.fields() {
        // Match the field type
        match f.get_reflect(&**msg) {
            ReflectFieldRef::Map(map) => {
                if map.is_empty() {
                    continue;
                }
                writeln!(
                    buf,
                    "{}{}:",
                    get_indentation(indent),
                    Colors::YELLOW.paint(f.name()).bold()
                )?;
                for (k, v) in &map {
                    match v {
                        ReflectValueRef::Message(_) => {
                            writeln!(
                                buf,
                                "{}{}:",
                                get_indentation(indent + 1),
                                Colors::BLUE.paint(k)
                            )?;
                        }
                        _ => {
                            write!(
                                buf,
                                "{}{}: ",
                                get_indentation(indent + 1),
                                Colors::BLUE.paint(k)
                            )?;
                        }
                    }
                    print_field(
                        buf,
                        "",
                        v,
                        f.proto(),
                        indent + 1,
                        first_line,
                    )?;
                }
            }
            ReflectFieldRef::Repeated(repeated) => {
                if repeated.is_empty() {
                    continue;
                }
                writeln!(
                    buf,
                    "{}{} {} {}",
                    get_indentation(indent),
                    Colors::GREEN.paint("# Nested").italic(),
                    Colors::GREEN.paint(f.name()).italic(),
                    Colors::GREEN.paint("structure").italic()
                )?;
                writeln!(
                    buf,
                    "{}{}:",
                    get_indentation(indent),
                    Colors::YELLOW.paint(f.name()).bold()
                )?;
                for v in repeated {
                    match v {
                        ReflectValueRef::Message(_) => {
                            print_field(
                                buf,
                                "",
                                v,
                                f.proto(),
                                indent,
                                first_line,
                            )?;
                        }
                        _ => {
                            write!(
                                buf,
                                "{}  {} ",
                                get_indentation(indent),
                                Colors::YELLOW.paint("-").bold(),
                            )?;
                            print_field(
                                buf,
                                "",
                                v,
                                f.proto(),
                                indent,
                                first_line,
                            )?;
                        }
                    }
                }
            }
            ReflectFieldRef::Optional(optional) => {
                if let Some(v) = optional.value() {
                    match v {
                        ReflectValueRef::Message(_) => {
                            writeln!(
                                buf,
                                "{}{} {} {}",
                                get_indentation(indent),
                                Colors::GREEN.paint("# Nested").italic(),
                                Colors::GREEN.paint(f.name()).italic(),
                                Colors::GREEN.paint("structure").italic()
                            )?;
                            writeln!(
                                buf,
                                "{}{}:",
                                get_indentation(indent),
                                Colors::YELLOW.paint(f.name()).bold()
                            )?;
                            print_field(
                                buf,
                                "",
                                v,
                                f.proto(),
                                indent,
                                first_line,
                            )?;
                        }
                        _ => {
                            print_field(
                                buf,
                                f.name(),
                                v,
                                f.proto(),
                                indent,
                                first_line,
                            )?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
