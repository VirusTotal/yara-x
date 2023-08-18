use crate::modules::prelude::*;
use crate::modules::protos::time::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[module_main]
fn main(_ctx: &ScanContext) -> Time {
    // Nothing to do, but we have to return our protobuf
    Time::new()
}

#[module_export]
fn now(_ctx: &ScanContext) -> Option<i64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    #[test]
    fn end2end() {
        let mut compiler = crate::compiler::Compiler::new();

        compiler
            .add_source(
                r#"import "time"
                rule rule_1 { condition: time.now() >= 0 }
                rule rule_2 { condition: time.now() <= 0 }
                rule rule_3 { condition: time.now() != 0 }
                rule rule_4 { condition: time.now() == 0 }
                "#,
            )
            .unwrap();

        let rules = compiler.build();
        let mut scanner = crate::scanner::Scanner::new(&rules);

        assert_eq!(scanner.scan(&[]).unwrap().matching_rules().len(), 2);
    }
}
