use crate::modules::prelude::*;
use crate::modules::protos::time::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod tests;

#[module_main]
fn main(_ctx: &ScanContext) -> Time {
    // Nothing to do, but we have to return our protobuf
    let time_proto = Time::new();
    time_proto
}

#[module_export(name = "now")]
fn now(ctx: &ScanContext) -> Option<i64> {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => return Some(n.as_secs() as i64),
        Err(_) => return None,
    }
}