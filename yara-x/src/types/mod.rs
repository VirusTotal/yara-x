use std::fmt::{Debug, Display, Formatter};
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use std::rc::Rc;

use bstr::ByteSlice;
use bstr::{BStr, BString};
use regex::bytes::RegexBuilder;
use serde::{Deserialize, Serialize};
use walrus::ValType;

mod array;
mod func;
mod map;
mod structure;

pub use array::*;
pub use func::*;
pub use map::*;
pub use structure::*;

/// The type of a YARA expression or identifier.
#[derive(Clone, Copy, PartialEq)]
pub enum Type {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Regexp,
    Struct,
    Array,
    Map,
    Func,
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Debug for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::Bool => write!(f, "boolean"),
            Self::String => write!(f, "string"),
            Self::Regexp => write!(f, "regexp"),
            Self::Struct => write!(f, "struct"),
            Self::Array => write!(f, "array"),
            Self::Map => write!(f, "map"),
            Self::Func => write!(f, "function"),
        }
    }
}

impl From<Type> for ValType {
    fn from(ty: Type) -> ValType {
        match ty {
            Type::Integer => ValType::I64,
            Type::Float => ValType::F64,
            Type::Bool => ValType::I32,
            Type::String => ValType::I64,
            _ => panic!("can not create WASM primitive type for `{}`", ty),
        }
    }
}

/// Contains information about a value.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Value<T> {
    /// Constant value. The value is known and it can not change at runtime.
    Const(T),
    /// Variable value. The value is known, but it can change at runtime.
    Var(T),
    /// Unknown value.
    Unknown,
}

impl<T> Value<T> {
    /// Returns true if the value is constant.
    ///
    /// A constant value can not change at runtime.
    #[inline]
    pub fn is_const(&self) -> bool {
        matches!(self, Value::Const(_))
    }

    /// Extract the value of type `T` contained inside [`Value`].
    ///
    /// Returns [`Some(T)`] if the value is known or [`None`] if it's unknown.
    pub fn extract(&self) -> Option<&T> {
        match self {
            Value::Const(v) | Value::Var(v) => Some(v),
            Value::Unknown => None,
        }
    }
}

impl Value<i64> {
    pub fn add(&self, other: &Value<i64>) -> Value<i64> {
        match (self, other) {
            (Value::Const(lhs), Value::Const(rhs)) => {
                match lhs.checked_add(*rhs) {
                    Some(r) => Value::Const(r),
                    None => Value::Unknown,
                }
            }
            (Value::Const(lhs), Value::Var(rhs))
            | (Value::Var(lhs), Value::Const(rhs))
            | (Value::Var(lhs), Value::Var(rhs)) => {
                match lhs.checked_add(*rhs) {
                    Some(r) => Value::Var(r),
                    None => Value::Unknown,
                }
            }
            (Value::Unknown, _) | (_, Value::Unknown) => Value::Unknown,
        }
    }
}

impl Value<f64> {
    pub fn add<T: Into<f64> + Copy>(&self, other: &Value<T>) -> Value<f64> {
        match (self, other) {
            (Value::Const(lhs), Value::Const(rhs)) => {
                Value::Const(lhs + (*rhs).into())
            }
            (Value::Const(lhs), Value::Var(rhs))
            | (Value::Var(lhs), Value::Const(rhs))
            | (Value::Var(lhs), Value::Var(rhs)) => {
                Value::Var(lhs + (*rhs).into())
            }
            (Value::Unknown, _) | (_, Value::Unknown) => Value::Unknown,
        }
    }
}

/// A simple wrapper around [`String`] that represents a regular expression.
///
/// The string must be enclosed in slashes (`/`), optionally followed by the
/// `i` or `s` modifiers, or both. Some example of valid strings are:
///
/// ```text
/// /foobar/
/// /foobar/i
/// /foobar/s
/// /foobar/is
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regexp(String);

impl Regexp {
    pub fn new<R: AsRef<str>>(regexp: R) -> Self {
        let regexp = regexp.as_ref();

        assert!(regexp.starts_with('/'));
        assert!(regexp[1..].contains('/'));

        Self(regexp.to_string())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns the portion of the regexp within the starting and ending slashes.
    ///
    /// For example, for `/foobar/` returns `foobar`.
    pub fn naked(&self) -> &str {
        &self.0[1..self.0.rfind('/').unwrap()]
    }

    pub fn case_insensitive(&self) -> bool {
        let modifiers = &self.0[self.0.rfind('/').unwrap()..];
        modifiers.contains('i')
    }

    pub fn dot_matches_new_line(&self) -> bool {
        let modifiers = &self.0[self.0.rfind('/').unwrap()..];
        modifiers.contains('s')
    }
}

/// A [`TypeValue`] contains information about the type, and possibly the
/// value of a YARA expression or identifier.
///
/// In the case of primitive types (integer, float, bool and string), the
/// value can be constant, variable, or unknown. Structs, arrays and maps
/// always have a reference to a [`Struct`], [`Array`] or [`Map`] respectively,
/// but those structures, arrays and maps don't contain actual values at
/// compile time, they only provide details about the type, like for example,
/// which are the fields in a struct, or what's the type of the items in an
/// array.
#[derive(Clone, Serialize, Deserialize)]
pub enum TypeValue {
    Unknown,
    Integer(Value<i64>),
    Float(Value<f64>),
    Bool(Value<bool>),
    String(Value<BString>),
    Regexp(Option<Regexp>),
    Struct(Rc<Struct>),
    Array(Rc<Array>),
    Map(Rc<Map>),

    // A TypeValue that contains a function is not serialized.
    #[serde(skip)]
    Func(Rc<Func>),
}

macro_rules! gen_arithmetic_op {
    ($name:ident, $op:tt, $checked_op:ident) => {
        pub fn $name(&self, rhs: &Self) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if let Some(value) = lhs.$checked_op(*rhs) {
                                if is_const {
                                    Self::Integer(Value::Const(value))
                                } else {
                                    Self::Integer(Value::Var(value))
                                }
                            } else {
                                Self::Integer(Value::Unknown)
                            }
                        }
                        _ => Self::Integer(Value::Unknown)
                    }
                }
                (Self::Integer(lhs), Self::Float(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Float(Value::Const(*lhs as f64 $op rhs))
                            } else {
                                Self::Float(Value::Var(*lhs as f64 $op rhs))
                            }
                        }
                        _ => Self::Float(Value::Unknown)
                    }
                }
                (Self::Float(lhs), Self::Integer(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Float(Value::Const(lhs $op *rhs as f64))
                            } else {
                                Self::Float(Value::Var(lhs $op *rhs as f64))
                            }
                        }
                        _ => Self::Float(Value::Unknown)
                    }
                }
                (Self::Float(lhs), Self::Float(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Float(Value::Const(lhs $op rhs))
                            } else {
                                Self::Float(Value::Var(lhs $op rhs))
                            }
                        }
                        _ => Self::Float(Value::Unknown)
                    }
                }
                _ => Self::Unknown,
            }
        }
    };
}

macro_rules! gen_bitwise_op {
    ($name:ident, $op:tt) => {
        pub fn $name(&self, rhs: &Self) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Integer(Value::Const(lhs.$op(rhs)))
                            } else {
                                Self::Integer(Value::Var(lhs.$op(rhs)))
                            }
                        }
                        _ => Self::Integer(Value::Unknown),
                    }
                }
                _ => Self::Unknown,
            }
        }
    };
}

macro_rules! gen_shift_op {
    ($name:ident, $op:tt) => {
        pub fn $name(&self, rhs: &Self) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            let overflow: bool;
                            let mut value = 0;
                            // First convert `rhs` to u32, which is the type accepted
                            // by both overflowing_shr and overflowing_lhr. If the
                            // conversion fails, it's because its value is too large and
                            // does not fit in a u32, or because it's negative. In both
                            // cases the result of the shift operation is 0.
                            if let Ok(rhs) = (*rhs).try_into() {
                                // Now that rhs is an u32 we can call overflowing_shr or
                                // overflowing_lhr.
                                (value, overflow) = lhs.$op(rhs);
                                // The semantics << and >> in YARA is that the right-side
                                // operand can be larger than the number of bits in the
                                // left-side, and in those cases the result is 0.
                                if overflow {
                                    value = 0;
                                }
                            }
                            if is_const {
                                Self::Integer(Value::Const(value))
                            } else {
                                Self::Integer(Value::Var(value))
                            }
                        }
                        _ => Self::Integer(Value::Unknown),
                    }
                }
                _ => Self::Unknown,
            }
        }
    };
}

macro_rules! gen_string_op {
    ($name:ident, $op:tt) => {
        pub fn $name(&self, rhs: &Self, case_insensitive: bool) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::String(lhs), Self::String(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            let r = if case_insensitive {
                                let lhs = lhs.to_ascii_lowercase();
                                let rhs = rhs.to_ascii_lowercase();
                                (&lhs).$op(&rhs)
                            } else {
                                (&lhs).$op(&rhs)
                            };
                            if is_const {
                                Self::Bool(Value::Const(r))
                            } else {
                                Self::Bool(Value::Var(r))
                            }
                        }
                        _ => Self::Bool(Value::Unknown),
                    }
                }
                _ => Self::Unknown,
            }
        }
    };
}

macro_rules! gen_comparison_op {
    ($name:ident, $op:tt) => {
        pub fn $name(&self, rhs: &Self) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Bool(Value::Const(lhs $op rhs))
                            } else {
                                Self::Bool(Value::Var(lhs $op rhs))
                            }
                        },
                        _ => Self::Bool(Value::Unknown)
                    }
                }
                (Self::Integer(lhs), Self::Float(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Bool(Value::Const((*lhs as f64) $op *rhs))
                            } else {
                                Self::Bool(Value::Var((*lhs as f64) $op *rhs))
                            }
                        },
                        _ => Self::Bool(Value::Unknown)
                    }
                }
                (Self::Float(lhs), Self::Integer(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Bool(Value::Const(*lhs $op (*rhs as f64)))
                            } else {
                                Self::Bool(Value::Var(*lhs $op (*rhs as f64)))
                            }
                        },
                        _ => Self::Bool(Value::Unknown)
                    }
                }
                (Self::Float(lhs), Self::Float(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Bool(Value::Const(lhs $op rhs))
                            } else {
                                Self::Bool(Value::Var(lhs $op rhs))
                            }
                        },
                        _ => Self::Bool(Value::Unknown)
                    }
                }
                (Self::String(lhs), Self::String(rhs)) => {
                    let is_const = lhs.is_const() && rhs.is_const();
                    match (lhs.extract(), rhs.extract()) {
                        (Some(lhs), Some(rhs)) => {
                            if is_const {
                                Self::Bool(Value::Const(lhs $op rhs))
                            } else {
                                Self::Bool(Value::Var(lhs $op rhs))
                            }
                        },
                        _ => Self::Bool(Value::Unknown)
                    }
                }
                _ => Self::Unknown,
            }
        }
    };
}

impl TypeValue {
    gen_arithmetic_op!(add, +, checked_add);
    gen_arithmetic_op!(sub, -, checked_sub);
    gen_arithmetic_op!(mul, *, checked_mul);
    gen_arithmetic_op!(div, /, checked_div);
    gen_arithmetic_op!(rem, %, checked_rem);

    gen_bitwise_op!(bitwise_and, bitand);
    gen_bitwise_op!(bitwise_or, bitor);
    gen_bitwise_op!(bitwise_xor, bitxor);

    gen_shift_op!(shl, overflowing_shl);
    gen_shift_op!(shr, overflowing_shr);

    gen_string_op!(contains_str, contains_str);
    gen_string_op!(starts_with_str, starts_with_str);
    gen_string_op!(ends_with_str, ends_with_str);
    gen_string_op!(equals_str, eq);

    gen_comparison_op!(gt, >);
    gen_comparison_op!(lt, <);
    gen_comparison_op!(ge, >=);
    gen_comparison_op!(le, <=);
    gen_comparison_op!(eq, ==);
    gen_comparison_op!(ne, !=);

    pub fn is_const(&self) -> bool {
        match self {
            TypeValue::Unknown => false,
            TypeValue::Integer(value) => value.is_const(),
            TypeValue::Float(value) => value.is_const(),
            TypeValue::Bool(value) => value.is_const(),
            TypeValue::String(value) => value.is_const(),
            TypeValue::Regexp(_) => false,
            TypeValue::Struct(_) => false,
            TypeValue::Array(_) => false,
            TypeValue::Map(_) => false,
            TypeValue::Func(_) => false,
        }
    }

    pub fn defined(&self) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::Integer(Value::Const(_)) => Self::Bool(Value::Const(true)),
            Self::Integer(Value::Var(_)) => Self::Bool(Value::Var(true)),
            Self::Float(Value::Const(_)) => Self::Bool(Value::Const(true)),
            Self::Float(Value::Var(_)) => Self::Bool(Value::Var(true)),
            Self::Bool(Value::Const(_)) => Self::Bool(Value::Const(true)),
            Self::Bool(Value::Var(_)) => Self::Bool(Value::Var(true)),
            Self::String(Value::Const(_)) => Self::Bool(Value::Const(true)),
            Self::String(Value::Var(_)) => Self::Bool(Value::Var(true)),

            _ => Self::Bool(Value::Unknown),
        }
    }

    pub fn not(&self) -> Self {
        if let Self::Unknown = self {
            Self::Unknown
        } else {
            match self.cast_to_bool() {
                Self::Bool(Value::Const(b)) => Self::Bool(Value::Const(!b)),
                Self::Bool(Value::Var(b)) => Self::Bool(Value::Var(!b)),
                Self::Bool(Value::Unknown) => Self::Bool(Value::Unknown),
                _ => unreachable!(),
            }
        }
    }

    pub fn bitwise_not(&self) -> Self {
        match self {
            Self::Integer(Value::Const(v)) => Self::Integer(Value::Const(!*v)),
            Self::Integer(Value::Var(v)) => Self::Integer(Value::Var(!*v)),
            Self::Integer(Value::Unknown) => Self::Integer(Value::Unknown),
            _ => Self::Unknown,
        }
    }

    pub fn minus(&self) -> Self {
        match self {
            Self::Integer(Value::Const(v)) => Self::Integer(Value::Const(-*v)),
            Self::Integer(Value::Var(v)) => Self::Integer(Value::Var(-*v)),
            Self::Integer(Value::Unknown) => Self::Integer(Value::Unknown),

            Self::Float(Value::Const(v)) => Self::Float(Value::Const(-*v)),
            Self::Float(Value::Var(v)) => Self::Float(Value::Var(-*v)),
            Self::Float(Value::Unknown) => Self::Float(Value::Unknown),

            _ => Self::Unknown,
        }
    }

    /// Compares the types of two [`TypeValue`] instances, returning true if
    /// they are equal. The values can differ, only the types are taken into
    /// account.
    ///
    /// Instances of [`TypeValue::Struct`] are equal if both structures have
    /// the same fields and the type of each field matches.
    pub fn eq_type(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Integer(_), Self::Integer(_)) => true,
            (Self::Float(_), Self::Float(_)) => true,
            (Self::String(_), Self::String(_)) => true,
            (Self::Bool(_), Self::Bool(_)) => true,
            (Self::Array(a), Self::Array(b)) => {
                a.deputy().eq_type(&b.deputy())
            }
            (Self::Map(a), Self::Map(b)) => match (a.as_ref(), b.as_ref()) {
                (Map::StringKeys { .. }, Map::StringKeys { .. }) => {
                    a.deputy().eq_type(&b.deputy())
                }
                (Map::IntegerKeys { .. }, Map::IntegerKeys { .. }) => {
                    a.deputy().eq_type(&b.deputy())
                }
                _ => false,
            },
            (Self::Struct(a), Self::Struct(b)) => a.eq(b),
            _ => false,
        }
    }

    pub fn matches(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::String(s), Self::Regexp(Some(regexp))) => {
                let is_const = s.is_const();
                if let Some(s) = s.extract() {
                    let matches = RegexBuilder::new(regexp.naked())
                        .case_insensitive(regexp.case_insensitive())
                        .dot_matches_new_line(regexp.dot_matches_new_line())
                        .build()
                        .unwrap()
                        .is_match(s);

                    if is_const {
                        Self::Bool(Value::Const(matches))
                    } else {
                        Self::Bool(Value::Var(matches))
                    }
                } else {
                    Self::Bool(Value::Unknown)
                }
            }
            (Self::String(_), Self::Regexp(_)) => Self::Bool(Value::Unknown),
            _ => Self::Unknown,
        }
    }

    pub fn ty(&self) -> Type {
        match self {
            Self::Unknown => Type::Unknown,
            Self::Integer(_) => Type::Integer,
            Self::Float(_) => Type::Float,
            Self::Bool(_) => Type::Bool,
            Self::String(_) => Type::String,
            Self::Regexp(_) => Type::Regexp,
            Self::Map(_) => Type::Map,
            Self::Struct(_) => Type::Struct,
            Self::Array(_) => Type::Array,
            Self::Func(_) => Type::Func,
        }
    }

    pub fn clone_without_value(&self) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::Integer(_) => Self::Integer(Value::Unknown),
            Self::Float(_) => Self::Float(Value::Unknown),
            Self::Bool(_) => Self::Bool(Value::Unknown),
            Self::String(_) => Self::String(Value::Unknown),
            Self::Regexp(_) => Self::Regexp(None),
            Self::Map(v) => Self::Map(v.clone()),
            Self::Struct(v) => Self::Struct(v.clone()),
            Self::Array(v) => Self::Array(v.clone()),
            Self::Func(v) => Self::Func(v.clone()),
        }
    }

    /// Casts a [`TypeValue`] to [`TypeValue::Bool`].
    ///
    /// # Panics
    ///
    /// If the [`TypeValue`] has a type that can't be casted to bool. Only
    /// integers, floats, and strings and bools can be casted to bool.
    pub fn cast_to_bool(&self) -> Self {
        match self {
            Self::Integer(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::Integer(Value::Var(i)) => Self::Bool(Value::Var(*i != 0)),
            Self::Integer(Value::Const(i)) => {
                Self::Bool(Value::Const(*i != 0))
            }

            Self::Float(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::Float(Value::Var(f)) => Self::Bool(Value::Var(*f != 0.0)),
            Self::Float(Value::Const(f)) => {
                Self::Bool(Value::Const(*f != 0.0))
            }

            Self::String(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::String(Value::Var(s)) => Self::Bool(Value::Var(s.len() > 0)),
            Self::String(Value::Const(s)) => {
                Self::Bool(Value::Const(s.len() > 0))
            }

            Self::Bool(Value::Unknown) => Self::Bool(Value::Unknown),
            Self::Bool(Value::Var(b)) => Self::Bool(Value::Var(*b)),
            Self::Bool(Value::Const(b)) => Self::Bool(Value::Const(*b)),

            _ => panic!("can not cast {:?} to bool", self),
        }
    }

    pub fn as_bstr(&self) -> &BStr {
        if let TypeValue::String(v) = self {
            v.extract()
                .expect("TypeValue doesn't have an associated value")
                .as_bstr()
        } else {
            panic!(
                "called `as_bstr` on TypeValue that is not TypeValue::String"
            )
        }
    }

    pub fn as_array(&self) -> Rc<Array> {
        if let TypeValue::Array(array) = self {
            array.clone()
        } else {
            panic!("called `as_array` on a TypeValue that is not TypeValue::Array")
        }
    }

    pub fn as_struct(&self) -> Rc<Struct> {
        if let TypeValue::Struct(structure) = self {
            structure.clone()
        } else {
            panic!("called `as_struct` on a TypeValue that is not TypeValue::Struct")
        }
    }

    pub fn as_map(&self) -> Rc<Map> {
        if let TypeValue::Map(map) = self {
            map.clone()
        } else {
            panic!("called `as_map` on a TypeValue that is not TypeValue::Map")
        }
    }

    pub fn as_func(&self) -> Rc<Func> {
        if let TypeValue::Func(func) = self {
            func.clone()
        } else {
            panic!(
                "called `as_func` on a TypeValue that is not TypeValue::Func"
            )
        }
    }

    pub fn as_integer(&self) -> i64 {
        if let TypeValue::Integer(value) = self {
            value
                .extract()
                .cloned()
                .expect("TypeValue doesn't have an associated value")
        } else {
            panic!("called `as_integer` on a TypeValue that is not TypeValue::Integer")
        }
    }

    pub fn as_float(&self) -> f64 {
        if let TypeValue::Float(value) = self {
            value
                .extract()
                .cloned()
                .expect("TypeValue doesn't have an associated value")
        } else {
            panic!("called `as_float` on a TypeValue that is not TypeValue::Float")
        }
    }

    pub fn as_bool(&self) -> bool {
        if let TypeValue::Bool(value) = self {
            value
                .extract()
                .cloned()
                .expect("TypeValue doesn't have an associated value")
        } else {
            panic!(
                "called `as_bool` on a TypeValue that is not TypeValue::Bool"
            )
        }
    }

    pub fn try_as_bool(&self) -> Option<bool> {
        if let TypeValue::Bool(value) = self {
            value.extract().cloned()
        } else {
            None
        }
    }

    pub fn try_as_integer(&self) -> Option<i64> {
        if let TypeValue::Integer(value) = self {
            value.extract().cloned()
        } else {
            None
        }
    }
}

impl Display for TypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Debug for TypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Bool(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "boolean({:?})", v)
                } else {
                    write!(f, "boolean(unknown)")
                }
            }
            Self::Integer(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "integer({:?})", v)
                } else {
                    write!(f, "integer(unknown)")
                }
            }
            Self::Float(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "float({:?})", v)
                } else {
                    write!(f, "float(unknown)")
                }
            }
            Self::String(v) => {
                if let Some(v) = v.extract() {
                    write!(f, "string({:?})", v)
                } else {
                    write!(f, "string(unknown)")
                }
            }
            Self::Regexp(v) => {
                if let Some(v) = v {
                    write!(f, "regexp({:?})", v)
                } else {
                    write!(f, "regexp(unknown)")
                }
            }
            Self::Map(_) => write!(f, "map"),
            Self::Struct(_) => write!(f, "struct"),
            Self::Array(_) => write!(f, "array"),
            Self::Func(_) => write!(f, "function"),
        }
    }
}

#[cfg(test)]
impl PartialEq for TypeValue {
    fn eq(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (Self::Unknown, Self::Unknown) => true,
            (Self::String(lhs), Self::String(rhs)) => lhs == rhs,
            (Self::Bool(lhs), Self::Bool(rhs)) => lhs == rhs,
            (Self::Integer(lhs), Self::Integer(rhs)) => lhs == rhs,
            (Self::Float(lhs), Self::Float(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TypeValue::{Bool, Float, Integer, String};
    use crate::types::TypeValue;
    use crate::types::Value::{Const, Unknown, Var};
    use bstr::BString;
    use pretty_assertions::assert_eq;

    #[test]
    fn add() {
        assert_eq!(
            TypeValue::Unknown.add(&Integer(Var(2))),
            TypeValue::Unknown
        );

        assert_eq!(
            Integer(Var(1)).add(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(Integer(Unknown).add(&Integer(Var(1))), Integer(Unknown));
        assert_eq!(Integer(Var(1)).add(&Integer(Unknown)), Integer(Unknown));
        assert_eq!(Integer(Var(1)).add(&Integer(Var(1))), Integer(Var(2)));
        assert_eq!(Integer(Const(1)).add(&Integer(Var(1))), Integer(Var(2)));

        assert_eq!(
            Integer(Const(1)).add(&Integer(Const(1))),
            Integer(Const(2))
        );

        assert_eq!(
            Integer(Const(1)).add(&Integer(Const(1))),
            Integer(Const(2))
        );

        assert_eq!(Integer(Unknown).add(&Float(Var(1.0))), Float(Unknown));
        assert_eq!(Integer(Var(1)).add(&Float(Var(1.0))), Float(Var(2.0)));
        assert_eq!(Float(Var(1.5)).add(&Float(Var(1.0))), Float(Var(2.5)));

        assert_eq!(
            Integer(Const(1)).add(&Float(Const(1.0))),
            Float(Const(2.0))
        );

        assert_eq!(
            Float(Const(1.5)).add(&Float(Const(1.0))),
            Float(Const(2.5))
        );
    }

    #[test]
    fn sub() {
        assert_eq!(
            TypeValue::Unknown.sub(&Integer(Var(2))),
            TypeValue::Unknown
        );

        assert_eq!(
            Integer(Var(1)).sub(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(Integer(Unknown).sub(&Integer(Var(1))), Integer(Unknown));
        assert_eq!(Integer(Var(1)).sub(&Integer(Unknown)), Integer(Unknown));
        assert_eq!(Integer(Var(2)).sub(&Integer(Var(1))), Integer(Var(1)));
        assert_eq!(Integer(Var(2)).sub(&Float(Var(1.0))), Float(Var(1.0)));
        assert_eq!(Float(Var(1.5)).sub(&Float(Var(1.0))), Float(Var(0.5)));
    }

    #[test]
    fn mul() {
        assert_eq!(
            TypeValue::Unknown.mul(&Integer(Var(2))),
            TypeValue::Unknown
        );

        assert_eq!(
            Integer(Var(1)).mul(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(Integer(Unknown).mul(&Integer(Var(1))), Integer(Unknown));
        assert_eq!(Integer(Var(1)).mul(&Integer(Unknown)), Integer(Unknown));
        assert_eq!(Integer(Var(2)).mul(&Integer(Var(2))), Integer(Var(4)));
        assert_eq!(Integer(Var(2)).mul(&Float(Var(2.0))), Float(Var(4.0)));
        assert_eq!(Float(Var(1.5)).mul(&Float(Var(2.0))), Float(Var(3.0)));
    }

    #[test]
    fn div() {
        assert_eq!(
            TypeValue::Unknown.div(&Integer(Var(2))),
            TypeValue::Unknown
        );

        assert_eq!(
            Integer(Var(1)).div(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(Integer(Unknown).div(&Integer(Var(1))), Integer(Unknown));
        assert_eq!(Integer(Var(1)).div(&Integer(Unknown)), Integer(Unknown));
        assert_eq!(Integer(Var(2)).div(&Integer(Var(2))), Integer(Var(1)));
        assert_eq!(Integer(Var(2)).div(&Float(Var(2.0))), Float(Var(1.0)));
        assert_eq!(Float(Var(3.0)).div(&Float(Var(2.0))), Float(Var(1.5)));
        assert_eq!(Integer(Var(2)).div(&Integer(Var(0))), Integer(Unknown));

        assert_eq!(
            Float(Var(2.0)).div(&Float(Var(0.0))),
            Float(Var(f64::INFINITY))
        );

        assert_eq!(
            Integer(Var(2)).div(&Float(Var(0.0))),
            Float(Var(f64::INFINITY))
        );
    }

    #[test]
    fn rem() {
        assert_eq!(
            TypeValue::Unknown.rem(&Integer(Var(2))),
            TypeValue::Unknown
        );

        assert_eq!(
            Integer(Var(1)).rem(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(Integer(Unknown).rem(&Integer(Var(1))), Integer(Unknown));
        assert_eq!(Integer(Var(1)).rem(&Integer(Unknown)), Integer(Unknown));
        assert_eq!(Integer(Var(3)).rem(&Integer(Var(2))), Integer(Var(1)));
        assert_eq!(Integer(Var(5)).rem(&Float(Var(2.0))), Float(Var(1.0)));
        assert_eq!(Float(Var(3.0)).rem(&Float(Var(2.0))), Float(Var(1.0)));
        assert_eq!(Integer(Var(2)).rem(&Integer(Var(0))), Integer(Unknown));
    }

    #[test]
    fn shl() {
        assert_eq!(
            TypeValue::Unknown.shl(&Bool(Var(true))),
            TypeValue::Unknown
        );

        assert_eq!(
            Bool(Var(true)).shl(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(Integer(Unknown).shl(&Integer(Var(1))), Integer(Unknown));
        assert_eq!(Integer(Var(1)).shl(&Integer(Unknown)), Integer(Unknown));
        assert_eq!(Integer(Var(4)).shl(&Integer(Var(1))), Integer(Var(8)));
        assert_eq!(Integer(Var(1)).shl(&Integer(Var(64))), Integer(Var(0)));
    }

    #[test]
    fn shr() {
        assert_eq!(
            TypeValue::Unknown.shr(&Bool(Var(true))),
            TypeValue::Unknown
        );

        assert_eq!(
            Bool(Var(true)).shr(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(Integer(Unknown).shr(&Integer(Var(1))), Integer(Unknown));
        assert_eq!(Integer(Var(1)).shr(&Integer(Unknown)), Integer(Unknown));
        assert_eq!(Integer(Var(1)).shr(&Integer(Var(1))), Integer(Var(0)));
        assert_eq!(Integer(Var(2)).shr(&Integer(Var(1))), Integer(Var(1)));
    }

    #[test]
    fn defined() {
        assert_eq!(TypeValue::Unknown.defined(), TypeValue::Unknown);
        assert_eq!(Bool(Var(true)).defined(), Bool(Var(true)));
        assert_eq!(Bool(Var(false)).defined(), Bool(Var(true)));
        assert_eq!(Integer(Var(0)).defined(), Bool(Var(true)));
        assert_eq!(Float(Var(0.0)).defined(), Bool(Var(true)));

        assert_eq!(String(Var(BString::from(""))).defined(), Bool(Var(true)));
    }
}
