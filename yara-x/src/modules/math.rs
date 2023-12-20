use crate::modules::prelude::*;
use crate::modules::protos::math::*;
use itertools::Itertools;
use num_traits::Pow;

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

#[module_export(name = "mean")]
fn mean_data(ctx: &ScanContext, offset: i64, length: i64) -> Option<f64> {
    let start = offset as usize;
    let end = start.saturating_add(length as usize);
    mean(ctx.scanned_data().get(start..end)?)
}

#[module_export(name = "mean")]
fn mean_string(ctx: &ScanContext, s: RuntimeString) -> Option<f64> {
    mean(s.as_bstr(ctx).as_bytes())
}

#[module_export(name = "serial_correlation")]
fn serial_correlation_data(
    ctx: &ScanContext,
    offset: i64,
    length: i64,
) -> Option<f64> {
    let start = offset as usize;
    let end = start.saturating_add(length as usize);
    serial_correlation(ctx.scanned_data().get(start..end)?)
}

#[module_export(name = "serial_correlation")]
fn serial_correlation_string(
    ctx: &ScanContext,
    s: RuntimeString,
) -> Option<f64> {
    serial_correlation(s.as_bstr(ctx).as_bytes())
}

fn entropy(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return None;
    }

    let mut distribution = [0u64; 256];
    for byte in data {
        distribution[*byte as usize] += 1;
    }

    let mut entropy: f64 = 0.0;
    for value in &distribution {
        if *value != 0 {
            let x = *value as f64 / data.len() as f64;
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

    let mut sum: f64 = 0.0;
    for (i, value) in distribution.iter().enumerate() {
        sum += f64::abs(i as f64 - mean) * *value as f64;
    }

    Some(sum / data.len() as f64)
}

fn mean(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return None;
    }

    let mut distribution = [0u64; 256];
    for byte in data {
        distribution[*byte as usize] += 1;
    }

    let mut sum: f64 = 0.0;
    for (i, value) in distribution.iter().enumerate() {
        sum += i as f64 * *value as f64;
    }

    Some(sum / data.len() as f64)
}

fn serial_correlation(data: &[u8]) -> Option<f64> {
    let mut scc1: f64 = data
        .iter()
        .map(|x| *x as f64)
        .tuple_windows()
        .map(|(x, y)| x * y)
        .sum();

    let scc2: f64 = data.iter().map(|x| *x as f64).sum::<f64>().pow(2);
    let scc3: f64 = data.iter().map(|x| (*x as f64).pow(2)).sum();

    if let (Some(first), Some(last)) = (data.first(), data.last()) {
        scc1 += (*first as f64) * (*last as f64)
    }

    let len = data.len() as f64;
    let scc = (len * scc1 - scc2) / (len * scc3 - scc2);

    if scc.is_nan() {
        Some(-100000.0)
    } else {
        Some(scc)
    }
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
            rule test { condition: math.max(-1,0) == 0 }"#,
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

    #[test]
    fn mean() {
        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.mean("ABCABC") == 66.0
            }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.mean(0, 3) == 66.0
            }"#,
            b"ABCABC"
        );
    }

    #[test]
    fn serial_correlation() {
        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.serial_correlation("BCA") == -0.5
            }"#,
            &[]
        );

        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.serial_correlation(1, 3) == -0.5
            }"#,
            b"ABCABC"
        );

        rule_true!(
            r#"
            import "math"
            rule test {
                condition:
                    math.serial_correlation(0, 0) == -100000.0
            }"#,
            b"ABCABC"
        )
    }
}
