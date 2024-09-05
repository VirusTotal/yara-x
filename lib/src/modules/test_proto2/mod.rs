use crate::modules::prelude::*;
use crate::modules::protos::test_proto2::NestedProto2;
use crate::modules::protos::test_proto2::TestProto2;
use crate::types::Struct;
use std::rc::Rc;

#[cfg(test)]
mod tests;

#[module_export(name = "add")]
pub(crate) fn add_i64(_ctx: &mut ScanContext, a: i64, b: i64) -> i64 {
    a + b
}

#[module_export(name = "add")]
pub(crate) fn add_f64(_ctx: &mut ScanContext, a: f64, b: f64) -> f64 {
    a + b
}

#[module_export(name = "uppercase")]
pub(crate) fn uppercase(
    ctx: &mut ScanContext,
    s: RuntimeString,
) -> RuntimeString {
    RuntimeString::new(s.as_bstr(ctx).to_uppercase())
}

#[module_export(name = "nested.nested_func")]
pub(crate) fn nested_func(_ctx: &mut ScanContext) -> bool {
    true
}

#[module_export(
    name = "nested_method",
    method_of = "test_proto2.NestedProto2"
)]
pub(crate) fn nested_method(
    _ctx: &mut ScanContext,
    structure: Rc<Struct>,
) -> bool {
    structure.field_by_name("nested_bool").unwrap().type_value.as_bool()
}

#[module_export]
pub(crate) fn undef_i64(_ctx: &mut ScanContext) -> Option<i64> {
    None
}

#[module_export]
fn head(ctx: &mut ScanContext, n: i64) -> Option<RuntimeString> {
    let head = ctx.scanned_data().get(0..n as usize)?;
    Some(RuntimeString::from_slice(ctx, head))
}

#[module_export]
fn get_foo(ctx: &mut ScanContext) -> Option<RuntimeString> {
    let proto = ctx.module_output::<TestProto2>()?;
    let foo = proto.string_foo.as_ref().cloned()?;
    Some(RuntimeString::new(foo))
}

#[module_export]
fn to_int(ctx: &ScanContext, string: RuntimeString) -> Option<i64> {
    let string = string.to_str(ctx).ok()?;
    string.parse::<i64>().ok()
}

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> TestProto2 {
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
    test.set_double_zero(0.0);

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
    test.set_double_one(1.0);

    test.set_string_foo("foo".to_string());
    test.set_string_bar("bar".to_string());

    test.set_bytes_foo("foo".as_bytes().to_vec());
    test.set_bytes_bar("bar".as_bytes().to_vec());

    test.set_bool_proto(true);
    test.set_file_size(data.len() as u64);

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
    nested.set_nested_bool(false);

    nested.nested_array_int64.push(1);
    nested.nested_array_int64.push(10);
    nested.nested_array_int64.push(100);

    test.nested = Some(nested.clone()).into();

    test.map_string_struct.insert("foo".to_string(), nested.clone());
    test.map_string_int64.insert("one".to_string(), 1);
    test.map_string_float.insert("one".to_string(), 1.0);
    test.map_string_string.insert("foo".to_string(), "FOO".to_string());
    test.map_string_bool.insert("foo".to_string(), true);

    test.map_int64_struct.insert(100, nested.clone());
    test.map_int64_int64.insert(100, 1000);
    test.map_int64_float.insert(100, 1000.0);
    test.map_int64_string.insert(100, "one thousand".to_string());
    test.map_int64_bool.insert(100, true);

    test.array_struct.push(nested.clone());

    let mut nested = nested.clone();
    nested.set_nested_bool(true);

    test.array_struct.push(nested);

    test
}
