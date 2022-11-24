use crate::modules::protos::test_proto2::ProgrammingLanguage;
use crate::modules::protos::test_proto2::ProgrammingLanguages;

use crate::scanner::ScanContext;
use yara_macros::module_main;

//#[member_of(Submessage)]
pub(crate) fn sum(a: i64, b: i64) -> i64 {
    a + b
}

#[module_main]
fn main(ctx: &ScanContext) -> ProgrammingLanguages {
    let data = ProgrammingLanguages::new();
    data
}
