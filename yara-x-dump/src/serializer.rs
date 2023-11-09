use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use protobuf::descriptor::FieldDescriptorProto;
use protobuf::reflect::MessageRef;
use protobuf::reflect::ReflectFieldRef;
use protobuf::reflect::ReflectValueRef;
use protobuf_support::text_format::quote_bytes_to;
use std::fmt::Write;
use yansi::Color;
use yansi::Paint;

use crate::dumper::exts::field_options;

use crate::Error;

// A struct that represents colors for output
struct Colors;

impl Colors {
    const GREEN: Color = Color::Green;
    const BLUE: Color = Color::Blue;
    const YELLOW: Color = Color::Yellow;
    const BROWN: Color = Color::RGB(222, 184, 135);
}

// A struct that represents options for a field values
#[derive(Debug, Default, Clone)]
struct ValueOptions {
    is_hex: bool,
    is_timestamp: bool,
}

// Write a value as a comment
//
// # Arguments
//
// * `value`: The value to write
//
// # Returns
//
// Returns a `String` which represents the value as a comment
fn write_as_a_comment(value: String) -> Paint<String> {
    Colors::BROWN.paint(format!("{} {}", "#", value))
}

// Print a field name with correct indentation
//
// # Arguments
//
// * `buf`: The buffer to write the field name to
// * `field_name`: The field name to write
// * `indent`: The indentation level
// * `is_first_line`: A boolean that indicates if the field name is the first
// line
//
// # Returns
//
// Returns a `Result<(), Error>` where the `Error` is any error that occurred
// during the process
//
// # Errors
//
// * `Error::FormattingError`: If the field name could not be written to the
// buffer
fn print_field_name(
    buf: &mut String,
    field_name: &str,
    indent: usize,
    is_first_line: &mut bool,
) -> Result<(), Error> {
    let mut indentation = get_indentation(indent);

    // If the field name is not empty, print it
    if !field_name.is_empty() {
        // If the field name is the first line, print the indentation with a
        // dash and the field name
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
                Colors::BLUE.paint(field_name).bold()
            )?;
            *is_first_line = false;
        // If the field name is not the first line, print the indentation and
        // the field name
        } else {
            write!(
                buf,
                "{}{}: ",
                indentation,
                Colors::BLUE.paint(field_name).bold()
            )?;
        }
    }
    Ok(())
}

// Print a field value with correct indentation for multiple value formats
//
// # Arguments
//
// * `buf`: The buffer to write the field value to
// * `value`: The field value to write
// * `value_options`: The value options for the field value
// * `indent`: The indentation level
// * `is_first_line`: A boolean that indicates if the field value is the first
// line
//
// # Returns
//
// Returns a `Result<(), Error>` where the `Error` is any error that occurred
// during the process
//
// # Errors
//
// * `Error::FormattingError`: If the field value could not be written to the
// buffer
fn print_field_value(
    buf: &mut String,
    value: ReflectValueRef,
    value_options: &ValueOptions,
    indent: usize,
    is_first_line: &mut bool,
) -> Result<(), Error> {
    // Match the field value type and print it in desired format
    match value {
        ReflectValueRef::Message(m) => {
            *is_first_line = true;
            // Recursively print the message
            get_yaml(&m, buf, indent + 1, is_first_line)?;
        }
        ReflectValueRef::Enum(d, v) => match d.value_by_number(v) {
            Some(e) => writeln!(buf, "{}", e.name())?,
            None => writeln!(buf, "{}", v)?,
        },
        ReflectValueRef::String(s) => {
            writeln!(
                buf,
                "{}{}{}",
                Colors::GREEN.paint("\""),
                Colors::GREEN.paint(s),
                Colors::GREEN.paint("\""),
            )?;
        }
        ReflectValueRef::Bytes(b) => {
            quote_bytes_to(b, buf);
            buf.push('\n');
        }
        ReflectValueRef::I32(v) => {
            // If the value has hex option turned on, print it in hex format
            let field_value = if value_options.is_hex {
                format!("0x{:x}", v)
            // If the value has timestamp option turned on, print it in
            // timestamp format
            } else if value_options.is_timestamp {
                format!(
                    "{} {}",
                    v,
                    write_as_a_comment(
                        DateTime::<Utc>::from_naive_utc_and_offset(
                            NaiveDateTime::from_timestamp_opt(v as i64, 0)
                                .unwrap(),
                            Utc,
                        )
                        .to_string()
                    )
                )
            // Otherwise, print it as a normal integer
            } else {
                v.to_string()
            };
            writeln!(buf, "{}", field_value)?;
        }
        ReflectValueRef::I64(v) => {
            // If the value has hex option turned on, print it in hex format
            let field_value = if value_options.is_hex {
                format!("0x{:x}", v)
            // If the value has timestamp option turned on, print it in
            // timestamp format
            } else if value_options.is_timestamp {
                format!(
                    "{} {}",
                    v,
                    DateTime::<Utc>::from_naive_utc_and_offset(
                        NaiveDateTime::from_timestamp_opt(v, 0).unwrap(),
                        Utc,
                    )
                )
            // Otherwise, print it as a normal integer
            } else {
                v.to_string()
            };
            writeln!(buf, "{}", field_value)?;
        }
        ReflectValueRef::U32(v) => {
            // If the value has hex option turned on, print it in hex format
            let field_value = if value_options.is_hex {
                format!("0x{:x}", v)
            // If the value has timestamp option turned on, print it in
            // timestamp format
            } else if value_options.is_timestamp {
                format!(
                    "{} {}",
                    v,
                    write_as_a_comment(
                        DateTime::<Utc>::from_naive_utc_and_offset(
                            NaiveDateTime::from_timestamp_opt(v as i64, 0)
                                .unwrap(),
                            Utc,
                        )
                        .to_string()
                    )
                )
            // Otherwise, print it as a normal integer
            } else {
                v.to_string()
            };
            writeln!(buf, "{}", field_value)?;
        }
        ReflectValueRef::U64(v) => {
            // If the value has hex option turned on, print it in hex format
            let field_value = if value_options.is_hex {
                format!("0x{:x}", v)
            // If the value has timestamp option turned on, print it in
            // timestamp format
            } else if value_options.is_timestamp {
                format!(
                    "{} {}",
                    v,
                    write_as_a_comment(
                        DateTime::<Utc>::from_naive_utc_and_offset(
                            NaiveDateTime::from_timestamp_opt(v as i64, 0)
                                .unwrap(),
                            Utc,
                        )
                        .to_string()
                    )
                )
            // Otherwise, print it as a normal integer
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
//
// # Arguments
//
// * `field_descriptor`: The field descriptor to get the value options for
//
// # Returns
//
// Returns a `ValueOptions` which is the value options for the field
fn get_value_options(field_descriptor: &FieldDescriptorProto) -> ValueOptions {
    field_options
        .get(&field_descriptor.options)
        .map(|options| ValueOptions {
            // Default for boolean is false
            is_hex: options.yaml_fmt() == "x",
            is_timestamp: options.yaml_fmt() == "t",
        })
        .unwrap_or_default()
}

// Print a field name and value
//
// # Arguments
//
// * `buf`: The buffer to write the field name and value to
// * `field_name`: The field name to write
// * `value`: The field value to write
// * `field_descriptor`: The field descriptor to get the value options for
// * `indent`: The indentation level
// * `is_first_line`: A boolean that indicates if the field name and value is
// the first line
//
// # Returns
//
// Returns a `Result<(), Error>` where the `Error` is any error that occurred
// during the process
//
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
//
// # Arguments
//
// * `indent`: The indentation level
//
// # Returns
//
// Returns a `String` which represents the indentation level
fn get_indentation(indent: usize) -> String {
    "    ".repeat(indent)
}

/// A function that returns a YAML output
///
/// # Arguments
///
/// * `msg`: The message to get the human-readable output for
/// * `buf`: The buffer to write the human-readable output to
/// * `indent`: The indentation level
/// * `first_line`: A boolean that indicates if the field name and value is
/// the first line
///
/// # Returns
///
/// Returns a `Result<(), Error>` where the `Error` is any error that occurred
/// during the process
pub fn get_yaml(
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
            // If the field is a message, print it recursively
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
                // Iterate over the map
                for (k, v) in &map {
                    match v {
                        // If the value is a message, print it recursively
                        ReflectValueRef::Message(_) => {
                            writeln!(
                                buf,
                                "{}{}:",
                                get_indentation(indent + 1),
                                Colors::BLUE.paint(k).bold()
                            )?;
                        }
                        // Otherwise, print the field name
                        _ => {
                            write!(
                                buf,
                                "{}{}: ",
                                get_indentation(indent + 1),
                                Colors::BLUE.paint(k).bold()
                            )?;
                        }
                    }
                    // Print the field value
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
            // If the field is a repeated field, print nested structure without
            // repeating the field name
            ReflectFieldRef::Repeated(repeated) => {
                if repeated.is_empty() {
                    continue;
                }
                writeln!(
                    buf,
                    "{}{}",
                    get_indentation(indent),
                    write_as_a_comment("Nested ".to_string() + f.name()),
                )?;
                writeln!(
                    buf,
                    "{}{}:",
                    get_indentation(indent),
                    Colors::YELLOW.paint(f.name()).bold()
                )?;
                // Iterate over the repeated field
                for v in repeated {
                    match v {
                        // If the value is a message, print it recursively
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
                        // Otherwise, print the field value
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
            // If the field is a singular field, print it
            ReflectFieldRef::Optional(optional) => {
                if let Some(v) = optional.value() {
                    match v {
                        // If the value is a message, print it recursively
                        ReflectValueRef::Message(_) => {
                            writeln!(
                                buf,
                                "{}{}",
                                get_indentation(indent),
                                write_as_a_comment(
                                    "Nested ".to_string() + f.name()
                                ),
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
                        // Otherwise, print the field value
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
