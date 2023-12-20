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

#[cfg(test)]
mod tests {
    #[test]
    fn min_and_max() {
        let mut compiler = crate::compiler::Compiler::new();

        compiler
            .add_source(
                r#"import "math"
                rule rule_1 { condition: math.min(1,2) == 1 }
                rule rule_2 { condition: math.min(2,2) == 2 }
                rule rule_3 { condition: math.min(-1,0) == -1 }
                rule rule_4 { condition: math.max(1,2) == 2 }
                rule rule_5 { condition: math.max(2,2) == 2 }
                rule rule_6 { condition: math.max(-1,0) == 0 }
                "#,
            )
            .unwrap();

        let rules = compiler.build();
        let mut scanner = crate::scanner::Scanner::new(&rules);

        assert_eq!(scanner.scan(&[]).unwrap().matching_rules().len(), 6);
    }
}
