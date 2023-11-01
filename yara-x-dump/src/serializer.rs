use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use protobuf::descriptor::FieldDescriptorProto;
use protobuf::reflect::MessageRef;
use protobuf::reflect::ReflectFieldRef;
use protobuf::reflect::ReflectValueRef;
use protobuf_support::text_format::quote_bytes_to;
use std::fmt::Write;
use yansi::Color::{Green, Yellow};
use yara_x_proto::exts::field_options;

use crate::Error;

// A struct that represents serializers
struct JsonSerializer;
struct YamlSerializer;
struct TomlSerializer;
struct XmlSerializer;

struct ValueOptions {
    is_hex: bool,
    is_timestamp: bool,
}

impl ValueOptions {
    fn new() -> Self {
        ValueOptions { is_hex: false, is_timestamp: false }
    }
}

/// A trait for any type that can serialize a message
pub(crate) trait Serializer {
    fn serialize(&self, message: String) -> Result<String, Error>;
}

/// Implement the trait for the JSON serializer
impl Serializer for JsonSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
        let value = serde_json::from_str::<serde_json::Value>(&message)?;
        Ok(serde_json::to_string_pretty(&value)?)
    }
}

/// Implement the trait for the YAML serializer
impl Serializer for YamlSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
        let value = serde_json::from_str::<serde_yaml::Value>(&message)?;
        Ok(serde_yaml::to_string(&value)?)
    }
}

/// Implement the trait for the TOML serializer
impl Serializer for TomlSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
        let value = serde_json::from_str::<toml::Value>(&message)?;
        Ok(toml::to_string_pretty(&value)?)
    }
}

/// Implement the trait for the XML serializer
impl Serializer for XmlSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
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
        let xml = xml_builder.build_from_json_string(&message)?;
        Ok(xml)
    }
}

/// A function that returns a trait object based on the format
pub fn get_serializer(format: &str) -> Result<Box<dyn Serializer>, Error> {
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
) {
    let mut indentation = "    ".repeat(indent);

    if field_name.is_empty() {
        return;
    }

    if *is_first_line {
        if !indentation.is_empty() {
            indentation.pop();
            indentation.pop();
        }
        write!(
            buf,
            "{}{} {}: ",
            indentation,
            Yellow.paint("-").bold(),
            field_name
        )
        .unwrap();
        *is_first_line = false;
    } else {
        write!(buf, "{}{}: ", indentation, field_name).unwrap();
    }
}

// Print a field value with correct indentation for multiple value formats
fn print_field_value(
    buf: &mut String,
    value: ReflectValueRef,
    value_options: &ValueOptions,
    indent: usize,
    is_first_line: &mut bool,
) {
    match value {
        ReflectValueRef::Message(m) => {
            *is_first_line = true;
            get_human_readable_output(&m, buf, indent + 1, is_first_line);
        }
        ReflectValueRef::Enum(d, v) => match d.value_by_number(v) {
            Some(e) => writeln!(buf, "{}", e.name()).unwrap(),
            None => writeln!(buf, "{}", v).unwrap(),
        },
        ReflectValueRef::String(s) => {
            quote_bytes_to(s.as_bytes(), buf);
            buf.push_str("\n");
        }
        ReflectValueRef::Bytes(b) => {
            quote_bytes_to(b, buf);
            buf.push_str("\n");
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
            writeln!(buf, "{}", field_value).unwrap();
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
            writeln!(buf, "{}", field_value).unwrap();
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
            writeln!(buf, "{}", field_value).unwrap();
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
            writeln!(buf, "{}", field_value).unwrap();
        }
        ReflectValueRef::Bool(v) => {
            writeln!(buf, "{}", v).unwrap();
        }
        ReflectValueRef::F32(v) => {
            writeln!(buf, "{}", v).unwrap();
        }
        ReflectValueRef::F64(v) => {
            writeln!(buf, "{}", v).unwrap();
        }
    }
}

// Print a field name and value
fn print_field(
    buf: &mut String,
    field_name: &str,
    value: ReflectValueRef,
    field_descriptor: &FieldDescriptorProto,
    indent: usize,
    is_first_line: &mut bool,
) {
    let value_options = field_options
        .get(&field_descriptor.options)
        .map(|options| ValueOptions {
            is_hex: options.hex_value.unwrap_or(false),
            is_timestamp: options.timestamp.unwrap_or(false),
        })
        .unwrap_or(ValueOptions::new());

    print_field_name(buf, field_name, indent, is_first_line);
    print_field_value(buf, value, &value_options, indent, is_first_line);
}

/// A function that returns a human-readable output
pub fn get_human_readable_output(
    msg: &MessageRef,
    buf: &mut String,
    indent: usize,
    first_line: &mut bool,
) -> String {
    let desc = msg.descriptor_dyn();

    // Iterate over the fields of the message
    for f in desc.fields() {
        let indentation = "    ".repeat(indent);

        // Match the field type
        match f.get_reflect(&**msg) {
            ReflectFieldRef::Map(map) => {
                if map.is_empty() {
                    continue;
                }
                writeln!(buf, "{}{}:", indentation, f.name()).unwrap();
                for (k, v) in &map {
                    print_field(
                        buf,
                        "",
                        k,
                        &f.proto(),
                        indent + 1,
                        first_line,
                    );
                    print_field(
                        buf,
                        "",
                        v,
                        &f.proto(),
                        indent + 1,
                        first_line,
                    );
                }
            }
            ReflectFieldRef::Repeated(repeated) => {
                if repeated.is_empty() {
                    continue;
                }
                writeln!(
                    buf,
                    "{}{} {} {}",
                    indentation,
                    Green.paint("# Nested").italic(),
                    Green.paint(f.name()).italic(),
                    Green.paint("structure").italic()
                )
                .unwrap();
                writeln!(
                    buf,
                    "{}{}:",
                    indentation,
                    Yellow.paint(f.name()).bold()
                )
                .unwrap();
                for v in repeated {
                    print_field(buf, "", v, &f.proto(), indent, first_line);
                }
            }
            ReflectFieldRef::Optional(optional) => {
                if let Some(v) = optional.value() {
                    print_field(
                        buf,
                        f.name(),
                        v,
                        &f.proto(),
                        indent,
                        first_line,
                    );
                }
            }
        }
    }

    return buf.to_string();
}
