use crate::modules::protos::test_proto2::NestedProto2;
use crate::modules::protos::test_proto2::TestProto2;
use bstr::{BString, ByteSlice};

use crate::scanner::ScanContext;
use crate::wasm;
use crate::wasm::string::RuntimeString;
use crate::wasm::*;
use linkme::distributed_slice;
use wasmtime::Caller;
use yara_x_macros::{module_main, wasm_export};

mod add_i64 {
    use super::*;

    #[wasm_export]
    pub(crate) fn add(
        _caller: Caller<'_, ScanContext>,
        a: i64,
        b: i64,
    ) -> i64 {
        a + b
    }
}

mod add_f64 {
    use super::*;

    #[wasm_export]
    pub(crate) fn add(
        _caller: Caller<'_, ScanContext>,
        a: f64,
        b: f64,
    ) -> f64 {
        a + b
    }
}

#[wasm_export]
pub(crate) fn uppercase(
    mut caller: Caller<'_, ScanContext>,
    s: string::RuntimeString,
) -> string::RuntimeString {
    let s = s.as_bstr(caller.data()).to_uppercase();

    let s_id = caller.data_mut().string_pool.get_or_intern(s);

    RuntimeString::Owned(s_id)
}

#[wasm_export]
pub(crate) fn undef_i64(_caller: Caller<'_, ScanContext>) -> MaybeUndef<i64> {
    MaybeUndef::Undef
}

#[module_main]
fn main(_ctx: &ScanContext) -> TestProto2 {
    let mut test = TestProto2::new();

    test.set_int32_zero(0);
    test.set_int64_zero(0);
    test.set_sint32_zero(0);
    test.set_sint64_zero(0);
    test.set_uint32_zero(0);
    test.set_uint64_zero(0);
    test.set_fixed32_zero(0);
    test.set_fixed64_zero(0);
    test.set_sfixed32_zero(0);
    test.set_sfixed64_zero(0);
    test.set_float_zero(0.0);

    test.set_int32_one(1);
    test.set_int64_one(1);
    test.set_sint32_one(1);
    test.set_sint64_one(1);
    test.set_uint32_one(1);
    test.set_uint64_one(1);
    test.set_fixed32_one(1);
    test.set_fixed64_one(1);
    test.set_sfixed32_one(1);
    test.set_sfixed64_one(1);
    test.set_float_one(1.0);

    test.set_string_foo("foo".to_string());
    test.set_string_bar("bar".to_string());

    test.set_bytes_foo("foo".as_bytes().to_vec());
    test.set_bytes_bar("bar".as_bytes().to_vec());

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

    let mut nested = NestedProto2::new();

    nested.set_nested_int32_zero(0);
    nested.set_nested_int64_zero(0);
    nested.set_nested_int32_one(1);
    nested.set_nested_int64_one(1);
    nested.nested_array_int64.push(1);
    nested.nested_array_int64.push(10);
    nested.nested_array_int64.push(100);

    test.nested = Some(nested).into();

    let mut nested = NestedProto2::new();

    nested.set_nested_int32_zero(0);
    nested.set_nested_int64_zero(0);
    nested.set_nested_int32_one(1);
    nested.set_nested_int64_one(1);
    nested.nested_array_int64.push(2);
    nested.nested_array_int64.push(20);
    nested.nested_array_int64.push(200);

    test.array_struct.push(nested);

    let mut nested = NestedProto2::new();

    nested.set_nested_int32_zero(0);
    nested.set_nested_int64_zero(0);
    nested.set_nested_int32_one(1);
    nested.set_nested_int64_one(1);
    nested.nested_array_int64.push(3);
    nested.nested_array_int64.push(30);
    nested.nested_array_int64.push(300);

    test.map_string_struct.insert("foo".to_string(), nested);
    test.map_string_int64.insert("one".to_string(), 1);
    test.map_string_string.insert("foo".to_string(), "FOO".to_string());

    let mut nested = NestedProto2::new();

    nested.set_nested_int32_zero(0);
    nested.set_nested_int64_zero(0);
    nested.set_nested_int32_one(1);
    nested.set_nested_int64_one(1);
    nested.nested_array_int64.push(4);
    nested.nested_array_int64.push(40);
    nested.nested_array_int64.push(400);

    test.map_int64_struct.insert(100, nested);
    test.map_int64_int64.insert(100, 100);
    test.map_int64_string.insert(100, "one hundred".to_string());

    test.set_bool_proto(true);

    test
}
