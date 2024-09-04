use crate::modules::prelude::*;
use crate::modules::protos::test_proto3::TestProto3;

#[module_main]
fn main(_data: &[u8], _meta: Option<&[u8]>) -> TestProto3 {
    let mut test = TestProto3::new();

    test.int32_zero = 0;
    test.int64_zero = 0;
    test.sint32_zero = 0;
    test.sint64_zero = 0;
    test.uint32_zero = 0;
    test.uint64_zero = 0;
    test.fixed32_zero = 0;
    test.fixed64_zero = 0;
    test.sfixed32_zero = 0;
    test.sfixed64_zero = 0;
    test.float_zero = 0.0;

    test.int32_one = 1;
    test.int64_one = 1;
    test.sint32_one = 1;
    test.sint64_one = 1;
    test.uint32_one = 1;
    test.uint64_one = 1;
    test.fixed32_one = 1;
    test.fixed64_one = 1;
    test.sfixed32_one = 1;
    test.sfixed64_one = 1;
    test.float_one = 1.0;

    test.string_foo = "foo".to_string();
    test.string_bar = "bar".to_string();

    test.bytes_foo = "foo".as_bytes().to_vec();
    test.bytes_bar = "bar".as_bytes().to_vec();

    test
}
