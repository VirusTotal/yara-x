use crate::modules::prelude::*;
use crate::modules::protos::test_proto3::NestedProto3;
use crate::modules::protos::test_proto3::TestProto3;

#[module_main]
fn main(_ctx: &ScanContext) -> TestProto3 {
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

    test.int32_one = 0;
    test.int64_one = 0;
    test.sint32_one = 0;
    test.sint64_one = 0;
    test.uint32_one = 0;
    test.uint64_one = 0;
    test.fixed32_one = 0;
    test.fixed64_one = 0;
    test.sfixed32_one = 0;
    test.sfixed64_one = 0;
    test.float_one = 0.0;

    test.string_foo = "foo".to_string();
    test.string_bar = "bar".to_string();

    test.bytes_foo = "foo".as_bytes().to_vec();
    test.bytes_bar = "bar".as_bytes().to_vec();

    test.array_int64.push(1);
    test.array_int64.push(10);
    test.array_int64.push(100);

    test.array_float.push(1.0);
    test.array_float.push(10.0);
    test.array_float.push(100.0);

    test.array_bool.push(false);
    test.array_bool.push(true);

    test.array_string.push("foo".to_string());
    test.array_string.push("bar".to_string());
    test.array_string.push("baz".to_string());

    let mut nested = NestedProto3::new();

    nested.nested_int32_zero = 0;
    nested.nested_int64_zero = 0;
    nested.nested_int32_one = 1;
    nested.nested_int64_one = 1;
    nested.nested_array_int64.push(1);
    nested.nested_array_int64.push(10);
    nested.nested_array_int64.push(100);

    test.nested = Some(nested).into();

    let mut nested = NestedProto3::new();

    nested.nested_int32_zero = 0;
    nested.nested_int64_zero = 0;
    nested.nested_int32_one = 1;
    nested.nested_int64_one = 1;
    nested.nested_array_int64.push(2);
    nested.nested_array_int64.push(20);
    nested.nested_array_int64.push(200);

    test.array_struct.push(nested);

    let mut nested = NestedProto3::new();

    nested.nested_int32_zero = 0;
    nested.nested_int64_zero = 0;
    nested.nested_int32_one = 1;
    nested.nested_int64_one = 1;
    nested.nested_array_int64.push(3);
    nested.nested_array_int64.push(30);
    nested.nested_array_int64.push(300);

    test.map_string_struct.insert("foo".to_string(), nested);
    test.map_string_int64.insert("one".to_string(), 1);
    test.map_string_string.insert("foo".to_string(), "FOO".to_string());

    let mut nested = NestedProto3::new();

    nested.nested_int32_zero = 0;
    nested.nested_int64_zero = 0;
    nested.nested_int32_one = 1;
    nested.nested_int64_one = 1;
    nested.nested_array_int64.push(4);
    nested.nested_array_int64.push(40);
    nested.nested_array_int64.push(400);

    //test.map_int64_struct.insert(100, nested);
    test.map_int64_int64.insert(100, 100);
    test.map_int64_string.insert(100, "one hundred".to_string());

    test
}
