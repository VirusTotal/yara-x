use protobuf::reflect::{EnumDescriptor, FieldDescriptor};

pub use yara::*;

use crate::yara::exts::field_options;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

/// Possible formats applied to values in YARA modules.
///
/// In the protobufs defining a YARA module, values can be formatted in various
/// ways. For example, you can define a field that represents a timestamp in the
/// following way:
///
/// ```
/// optional uint32 my_timestamp = 1 [(yara.field_options).fmt = "t"];
/// ```
///
/// Or a field that should be formatted as an hexadecimal number:
///
/// ```
/// optional uint32 my_flags = 2 [(yara.field_options).fmt = "x"];
/// ```
///
/// This enum represents the different formats that can be applied to values in
/// YARA modules.
#[derive(Debug, Clone)]
pub enum FieldFormat {
    None,
    Hex,
    Timestamp,
    Flags(EnumDescriptor),
}

/// Given a field descriptor, returns the format that should be applied to its
/// value, if any.
pub fn get_field_format(field_descriptor: &FieldDescriptor) -> FieldFormat {
    let opts = match field_options.get(&field_descriptor.proto().options) {
        Some(opts) => opts,
        None => return FieldFormat::None,
    };

    let fmt = opts.fmt();

    if fmt == "x" {
        return FieldFormat::Hex;
    } else if fmt == "t" {
        return FieldFormat::Timestamp;
    }

    let msg_descriptor = field_descriptor.containing_message();
    let file_descriptor = msg_descriptor.file_descriptor();

    // Check if format is something like `flags:ENUM_TYPE`.
    if let Some(flags_enum) = fmt.strip_prefix("flags:") {
        if let Some(flags_enum) =
            file_descriptor.enums().find(|e| e.name() == flags_enum)
        {
            return FieldFormat::Flags(flags_enum);
        } else {
            panic!(
                "field `{}` declared as `flags:{}`, but enum `{}` was not found",
                field_descriptor.full_name(),
                flags_enum,
                flags_enum
            )
        }
    }

    // If the format is not "x", "t", or "flags:ENUM_TYPE", and it's not empty,
    // it could be a custom format string (e.g. "{:#x}"). In this case,
    // we don't have a specific ValueFormat enum variant, so we treat it as None
    // for now. The actual formatting will be handled directly where this
    // function's return value is used, by checking if `fmt` is non-empty.
    // However, the original panic for unknown simple formats like "x", "t"
    // should be preserved if fmt is not a flags type and not x or t.
    // For now, to keep changes minimal, we'll assume that if it's not x, t, or flags,
    // and it's not empty, it's an invalid *simple* format specifier.
    // More complex format strings will pass through as ValueFormat::None
    // and need to be handled by the caller if direct string formatting is desired.
    if !fmt.is_empty() {
        // This part of the logic might need refinement if we want to support
        // arbitrary format strings directly through ValueFormat.
        // For now, an unknown non-empty fmt that is not "x", "t", or "flags:..."
        // is considered an error, similar to the original code.
        panic!(
            "invalid format option `{}` for field `{}`",
            fmt,
            field_descriptor.full_name(),
        );
    }

    FieldFormat::None
}
