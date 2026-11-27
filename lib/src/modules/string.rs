use crate::mods::prelude::*;
use crate::modules::protos::string::*;

fn main(_ctx: &mut ModuleContext, _data: &[u8]) -> Result<String, ModuleError> {
    // Nothing to do, but we have to return our protobuf
    Ok(String::new())
}

/// Converts a string to an integer.
#[module_export]
fn to_int(ctx: &ScanContext, string: RuntimeString) -> Option<i64> {
    let string = string.to_str(ctx).ok()?;
    string.parse::<i64>().ok()
}

/// Converts a string to an integer in the given base.
#[module_export(name = "to_int")]
fn to_int_base(
    ctx: &ScanContext,
    string: RuntimeString,
    base: i64,
) -> Option<i64> {
    let base: u32 = base.try_into().ok()?;
    if !(2..=36).contains(&base) {
        return None;
    }
    let string = string.to_str(ctx).ok()?;
    i64::from_str_radix(string, base).ok()
}

/// Returns the length of the string.
#[module_export]
fn length(ctx: &ScanContext, string: RuntimeString) -> Option<i64> {
    Some(string.as_bstr(ctx).len().try_into().unwrap())
}

/// `ScannedDataSlice` panics in `into_wasm_with_ctx` when `length >= u16::MAX`.
const MAX_SCANNED_SLICE: usize = u16::MAX as usize;

/// Replaced output larger than this is undefined, so a rule cannot force a
/// multi-megabyte allocation.
const MAX_REPLACE_BYTES: usize = 1_048_576;

fn runtime_string_from_bytes(ctx: &ScanContext, bytes: &[u8]) -> RuntimeString {
    if bytes.len() >= MAX_SCANNED_SLICE {
        RuntimeString::new(bytes.to_vec())
    } else {
        RuntimeString::from_slice(ctx, bytes)
    }
}

/// Drops leading and trailing bytes for which `drop_byte` is true.
///
/// An input that is entirely dropped yields an empty slice, not a panic.
fn trim_bytes<F>(bytes: &[u8], mut drop_byte: F) -> &[u8]
where
    F: FnMut(u8) -> bool,
{
    let start = bytes.iter().take_while(|b| drop_byte(**b)).count();
    let trailing = bytes.iter().rev().take_while(|b| drop_byte(**b)).count();
    let end = bytes.len() - trailing;
    if start >= end { b"" } else { &bytes[start..end] }
}

fn replaced_len(
    hay_len: usize,
    from_len: usize,
    to_len: usize,
    count: usize,
) -> Option<usize> {
    let removed = count.checked_mul(from_len)?;
    let added = count.checked_mul(to_len)?;
    hay_len.checked_sub(removed)?.checked_add(added)
}

/// Returns the byte offset of the first occurrence of `needle`.
///
/// Undefined when `needle` is empty, absent, or the offset does not fit in
/// an `i64`.
#[module_export]
fn index_of(
    ctx: &ScanContext,
    string: RuntimeString,
    needle: RuntimeString,
) -> Option<i64> {
    let needle = needle.as_bstr(ctx);
    if needle.is_empty() {
        return None;
    }
    let pos = string.as_bstr(ctx).find(needle)?;
    i64::try_from(pos).ok()
}

/// Strips leading and trailing ASCII whitespace.
///
/// Whitespace is space, tab, LF, FF, and CR (`u8::is_ascii_whitespace`).
/// A string that is entirely whitespace yields a defined empty string.
#[module_export]
fn trim(ctx: &ScanContext, string: RuntimeString) -> RuntimeString {
    let trimmed = string.as_bstr(ctx).trim_with(|c| {
        u8::try_from(c).is_ok_and(|b| b.is_ascii_whitespace())
    });
    runtime_string_from_bytes(ctx, trimmed)
}

/// Strips leading and trailing bytes that appear in `cutset`.
///
/// An empty `cutset` returns `string` unchanged. This walks bytes, because
/// `ByteSlice::trim_with` decodes UTF-8 and would miss a byte such as `0xFF`.
#[module_export(name = "trim")]
fn trim_cutset(
    ctx: &ScanContext,
    string: RuntimeString,
    cutset: RuntimeString,
) -> RuntimeString {
    let cut = cutset.as_bstr(ctx);
    if cut.is_empty() {
        return string;
    }
    let trimmed = trim_bytes(string.as_bstr(ctx), |b| cut.contains(&b));
    runtime_string_from_bytes(ctx, trimmed)
}

/// Returns `string` with its bytes reversed.
#[module_export]
fn reverse(ctx: &ScanContext, string: RuntimeString) -> RuntimeString {
    let mut bytes = string.as_bstr(ctx).to_vec();
    bytes.reverse();
    RuntimeString::new(bytes)
}

/// Replaces every non-overlapping occurrence of `from` with `to`.
///
/// Undefined when `from` is empty, when the output size overflows, or when
/// the output would exceed [`MAX_REPLACE_BYTES`]. A missing `from` returns
/// the original string.
#[module_export]
fn replace(
    ctx: &ScanContext,
    string: RuntimeString,
    from: RuntimeString,
    to: RuntimeString,
) -> Option<RuntimeString> {
    let rewrite = {
        let from_bytes = from.as_bstr(ctx);
        if from_bytes.is_empty() {
            return None;
        }
        let hay = string.as_bstr(ctx);
        let to_bytes = to.as_bstr(ctx);
        let count = hay.find_iter(from_bytes).count();
        if count == 0 {
            false
        } else {
            let output_len = replaced_len(
                hay.len(),
                from_bytes.len(),
                to_bytes.len(),
                count,
            )?;
            if output_len > MAX_REPLACE_BYTES {
                return None;
            }
            true
        }
    };

    if !rewrite {
        return Some(string);
    }

    let replaced =
        string.as_bstr(ctx).replace(from.as_bstr(ctx), to.as_bstr(ctx));
    Some(RuntimeString::new(replaced))
}

#[cfg(test)]
mod tests {
    use crate::tests::rule_false;
    use crate::tests::rule_true;
    use crate::tests::test_rule;

    #[test]
    fn length() {
        rule_true!(
            r#"
            import "string"
            rule test { condition: string.length("AXsx00ERS") == 9 }"#,
            &[]
        );

        rule_false!(
            r#"
            import "string"
            rule test { condition: string.length("AXsx00ERS") > 9 }"#,
            &[]
        );

        rule_false!(
            r#"
            import "string"
            rule test { condition: string.length("AXsx00ERS") < 9 }"#,
            &[]
        );
    }

    #[test]
    fn to_int() {
        rule_true!(
            r#"
            import "string"
            rule test { condition: string.to_int("1234") == 1234 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.to_int("-10") == -10 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.to_int("A", 16) == 10 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.to_int("011", 8) == 9 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.to_int("-011", 8) == -9 }"#,
            &[]
        );
    }

    #[test]
    fn index_of() {
        rule_true!(
            r#"
            import "string"
            rule test { condition: string.index_of("a\x00b\xffc", "\x00") == 1 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.index_of("a\x00b\xffc", "\xff") == 3 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: not defined string.index_of("abc", "z") }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: not defined string.index_of("abc", "") }"#,
            &[]
        );
    }

    #[test]
    fn trim() {
        rule_true!(
            r#"
            import "string"
            rule test { condition: string.trim("  a\x00b\xff  ") == "a\x00b\xff" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.trim(" \t\r\n") == "" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.trim("\x00ab\xff\x00", "\x00") == "ab\xff" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.trim("\xff\xff", "\xff") == "" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.trim(" ab ", "") == " ab " }"#,
            &[]
        );
    }

    #[test]
    fn reverse() {
        rule_true!(
            r#"
            import "string"
            rule test { condition: string.reverse("a\x00\xff") == "\xff\x00a" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.reverse("\xc3\xa9") == "\xa9\xc3" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            import "string"
            rule test { condition: string.reverse(math.to_string(123)) == "321" }"#,
            &[]
        );
    }

    #[test]
    fn replace() {
        rule_true!(
            r#"
            import "string"
            rule test { condition: string.replace("a\x00b\xff", "\x00", ".") == "a.b\xff" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: string.replace("aaa", "aa", "b") == "ba" }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test { condition: not defined string.replace("abc", "", "x") }"#,
            &[]
        );

        rule_true!(
            r#"
            import "string"
            rule test {
                condition:
                    defined string.replace("a\xffc", "z", "q") and
                    string.replace("a\xffc", "z", "q") == "a\xffc"
            }"#,
            &[]
        );
    }

    #[test]
    fn replace_output_limit() {
        assert_eq!(super::replaced_len(1, 1, 1_048_576, 1), Some(1_048_576));
        let over = super::replaced_len(1, 1, 1_048_577, 1).unwrap();
        assert!(over > super::MAX_REPLACE_BYTES);
        assert!(super::replaced_len(usize::MAX, 1, 2, usize::MAX).is_none());

        let big = "A".repeat(1_048_577);
        let rule = format!(
            "import \"string\"\nrule test {{ condition: not defined string.replace(\"Z\", \"Z\", \"{big}\") }}"
        );
        rule_true!(rule.as_str(), &[]);
    }
}

register_module!("string", String, main);
