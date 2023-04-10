use crate::modules::prelude::*;
use crate::modules::protos::time::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[module_main]
fn main(_ctx: &ScanContext) -> Time {
    // Nothing to do, but we have to return our protobuf
    let time_proto = Time::new();
    time_proto
}

#[module_export(name = "now")]
fn time_now(ctx: &ScanContext) -> Option<i64> {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => return Some(n.as_secs() as i64),
        Err(_) => return None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn end2end() {
        let rules = crate::compiler::Compiler::new()
            .add_source(
                r#"import "time"
                rule rule_1 { condition: time.now() >= 0 }
                rule rule_2 { condition: time.now() <= 0 }
                rule rule_3 { condition: time.now() != 0 }
                rule rule_4 { condition: time.now() == 0 }
                "#,
            )
            .unwrap()
            .build()
            .unwrap();

        let mut scanner = crate::scanner::Scanner::new(&rules);

        assert_eq!(scanner.scan(&[]).num_matching_rules(), 2);
    }
}
