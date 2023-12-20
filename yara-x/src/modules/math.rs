use crate::modules::prelude::*;
use crate::modules::protos::math::*;

#[module_main]
fn main(_data: &[u8]) -> Math {
    // Nothing to do, but we have to return our protobuf
    Math::new()
}

#[module_export]
fn min(_ctx: &ScanContext, a: i64, b: i64) -> i64 {
    i64::min(a, b)
}

#[module_export]
fn max(_ctx: &ScanContext, a: i64, b: i64) -> i64 {
    i64::max(a, b)
}

#[module_export(name = "entropy")]
fn entropy_data(ctx: &ScanContext, offset: i64, length: i64) -> Option<f64> {
    let start = offset as usize;
    let end = start.saturating_add(length as usize);
    entropy(ctx.scanned_data().get(start..end)?)
}

#[module_export(name = "entropy")]
fn entropy_string(ctx: &ScanContext, s: RuntimeString) -> Option<f64> {
    entropy(s.as_bstr(ctx).as_bytes())
}

#[module_export(name = "deviation")]
fn deviation_data(
    ctx: &ScanContext,
    offset: i64,
    length: i64,
    mean: f64,
) -> Option<f64> {
    let start = offset as usize;
    let end = start.saturating_add(length as usize);
    deviation(ctx.scanned_data().get(start..end)?, mean)
}

#[module_export(name = "deviation")]
fn deviation_string(
    ctx: &ScanContext,
    s: RuntimeString,
    mean: f64,
) -> Option<f64> {
    deviation(s.as_bstr(ctx).as_bytes(), mean)
}

fn entropy(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return None;
    }

    let mut distribution = [0u64; 256];

    for byte in data {
        distribution[*byte as usize] += 1;
    }

    let total: u64 = distribution.iter().sum();
    let mut entropy: f64 = 0.0;

    for value in &distribution {
        if *value != 0 {
            let x = *value as f64 / total as f64;
            entropy -= x * f64::log2(x);
        }
    }

    Some(entropy)
}

fn deviation(data: &[u8], mean: f64) -> Option<f64> {
    if data.is_empty() {
        return None;
    }

    let mut distribution = [0u64; 256];

    for byte in data {
        distribution[*byte as usize] += 1;
    }

    let mut total: f64 = 0.0;
    let mut sum: f64 = 0.0;

    for (i, value) in distribution.iter().enumerate() {
        total += *value as f64;
        sum += f64::abs(i as f64 - mean) * *value as f64;
    }

    Some(sum / total)
}

#[cfg(test)]
mod tests {
    use crate::tests::rule_true;
    use crate::tests::test_rule;

    #[test]
    fn min_and_max() {
        rule_true!(
            r#"
            import "math"
            rule test { condition: math.min(1,2) == 1 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test { condition: math.min(-1,0) == -1 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test { condition: math.max(1,2) == 2 }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test { condition: math.min(-1,0) == 0 }"#,
            &[]
        );
    }

    #[test]
    fn entropy() {
        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.entropy("AAAAA") == 0.0
            }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.entropy("AABB") == 1.0
            }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.entropy(2,3) == 0.0
            }"#,
            b"CCAAACC"
        );
    }

    #[test]
    fn deviation() {
        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.deviation("AAAAA", 0.0) == 65.0
            }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.deviation("ABAB", 65.0) == 0.5
            }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.deviation(2, 4, 65.0) == 0.5
            }"#,
            b"ABABABAB"
        );
    }
}
