use std::borrow::Cow;

use crate::modules::prelude::*;
use crate::modules::protos::console::*;

#[module_main]
fn main(_data: &[u8], _meta: Option<&[u8]>) -> Result<Console, ModuleError> {
    // Nothing to do, but we have to return our protobuf
    Ok(Console::new())
}

/// Logs a string to the console.
#[module_export(name = "log")]
fn log_str(ctx: &mut ScanContext, string: RuntimeString) -> bool {
    ctx.console_log(format!("{}", string.as_bstr(ctx)));
    true
}

/// Logs a string with a message to the console.
#[module_export(name = "log")]
fn log_msg_str(
    ctx: &mut ScanContext,
    message: RuntimeString,
    string: RuntimeString,
) -> bool {
    ctx.console_log(format!(
        "{}{}",
        message.as_bstr(ctx),
        string.as_bstr(ctx)
    ));
    true
}

pub fn escape(bytes: &[u8]) -> Cow<'_, str> {
    // First, try to interpret as UTF-8
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            // If invalid UTF-8, you must allocate anyway
            return Cow::Owned(
                bytes
                    .iter()
                    .flat_map(|&b| std::ascii::escape_default(b))
                    .map(|b| b as char)
                    .collect(),
            );
        }
    };

    // Check if escaping is needed
    let needs_escape = s.chars().any(|c| {
        matches!(c, '\n' | '\r' | '\t' | '\\' | '"') || c.is_control()
    });

    if !needs_escape {
        // Zero-copy: borrow directly
        return Cow::Borrowed(s);
    }

    Cow::Owned(bytes.escape_ascii().to_string())
}

/// Given an offset and length return Option<String> where the string is the
/// escaped ascii slice of scanned data. If either offset is negative or (offset
/// + length) wraps, the result will be None.
fn get_data<'a>(
    ctx: &'a mut ScanContext,
    offset: i64,
    length: i64,
) -> Option<Cow<'a, str>> {
    ctx.scanned_data()?
        .get(offset as usize..(offset + length) as usize)
        .map(escape)
}

#[module_export(name = "log")]
fn log_bytes(ctx: &mut ScanContext, offset: i64, length: i64) -> bool {
    let message = match get_data(ctx, offset, length) {
        Some(data) => format!("{}", data),
        None => return true,
    };

    ctx.console_log(message);
    true
}

#[module_export(name = "log")]
fn log_msg_bytes(
    ctx: &mut ScanContext,
    message: RuntimeString,
    offset: i64,
    length: i64,
) -> bool {
    let message = message.as_bstr(ctx).to_string();
    let message = match get_data(ctx, offset, length) {
        Some(data) => format!("{}{}", message, data),
        None => return true,
    };

    ctx.console_log(message);
    true
}

#[module_export(name = "log")]
fn log_bool(ctx: &mut ScanContext, b: bool) -> bool {
    ctx.console_log(format!("{b}"));
    true
}

/// Logs a boolean value with a message to the console.
#[module_export(name = "log")]
fn log_msg_bool(
    ctx: &mut ScanContext,
    message: RuntimeString,
    b: bool,
) -> bool {
    ctx.console_log(format!("{}{}", message.as_bstr(ctx), b));
    true
}

/// Logs an integer value to the console.
#[module_export(name = "log")]
fn log_int(ctx: &mut ScanContext, i: i64) -> bool {
    ctx.console_log(format!("{i}"));
    true
}

/// Logs an integer value with a message to the console.
#[module_export(name = "log")]
fn log_msg_int(ctx: &mut ScanContext, message: RuntimeString, i: i64) -> bool {
    ctx.console_log(format!("{}{}", message.as_bstr(ctx), i));
    true
}

/// Logs a float value to the console.
#[module_export(name = "log")]
fn log_float(ctx: &mut ScanContext, f: f64) -> bool {
    ctx.console_log(format!("{f}"));
    true
}

/// Logs a float value with a message to the console.
#[module_export(name = "log")]
fn log_msg_float(
    ctx: &mut ScanContext,
    message: RuntimeString,
    f: f64,
) -> bool {
    ctx.console_log(format!("{}{}", message.as_bstr(ctx), f));
    true
}

/// Logs an integer value as a hexadecimal string to the console.
#[module_export(name = "hex")]
fn log_hex(ctx: &mut ScanContext, i: i64) -> bool {
    ctx.console_log(format!("0x{i:x}"));
    true
}

/// Logs an integer value as a hexadecimal string with a message to the console.
#[module_export(name = "hex")]
fn log_msg_hex(ctx: &mut ScanContext, message: RuntimeString, i: i64) -> bool {
    ctx.console_log(format!("{}0x{:x}", message.as_bstr(ctx), i));
    true
}

#[cfg(test)]
mod tests {

    #[test]
    fn log() {
        let rules = crate::compile(
            r#"
            import "console"
            rule test {
                condition:
                    console.log("foo") and
                    console.log("bar: ", 1) and
                    console.log("baz: ", 3.14) and
                    console.log(10) and
                    console.log(6.28) and
                    console.log(true) and
                    console.log("bool: ", true) and
                    console.hex(10) and
                    console.hex("qux: ", 255) and
                    console.log("hello ", "world!") and
                    console.log(0, 4)
            }
            "#,
        )
        .unwrap();

        let mut messages = vec![];

        crate::scanner::Scanner::new(&rules)
            .console_log(|message| messages.push(message))
            .scan(b"\x00\x11ABC")
            .expect("scan should not fail");

        assert_eq!(
            messages,
            vec![
                "foo",
                "bar: 1",
                "baz: 3.14",
                "10",
                "6.28",
                "true",
                "bool: true",
                "0xa",
                "qux: 0xff",
                "hello world!",
                r"\x00\x11AB",
            ]
        );
    }
}

inventory::submit! {
    super::YaraModule {
        name: "console",
        root_descriptor: <Console as ::protobuf::MessageFull>::descriptor,
        main_fn: Some(__main__ as super::YaraModuleMainFn),
        rust_module_name: Some(module_path!()),
    }
}
