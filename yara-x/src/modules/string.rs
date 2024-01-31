use crate::modules::prelude::*;
use crate::modules::protos::string::*;

#[module_main]
fn main(_data: &[u8]) -> String {
    // Nothing to do, but we have to return our protobuf
    String::new()
}

#[module_export]
fn to_int(ctx: &ScanContext, string: RuntimeString) -> Option<i64> {
    let string = string.to_str(ctx).ok()?;
    string.parse::<i64>().ok()
}

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

#[module_export]
fn length(ctx: &ScanContext, string: RuntimeString) -> Option<i64> {
    Some(string.as_bstr(ctx).len().try_into().unwrap())
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
}
