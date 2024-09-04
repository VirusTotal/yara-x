use crate::modules::prelude::*;
use crate::modules::protos::time::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[module_main]
fn main(_data: &[u8], _meta: Option<&[u8]>) -> Time {
    // Nothing to do, but we have to return our protobuf
    Time::new()
}

#[module_export]
fn now(_ctx: &ScanContext) -> Option<i64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use crate::tests::rule_true;
    use crate::tests::test_rule;

    #[test]
    fn now() {
        rule_true!(
            r#"
            import "time" 
            rule test { condition: time.now() >= 0 }"#,
            &[]
        );
    }
}
