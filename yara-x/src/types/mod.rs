use std::fmt::{Debug, Display, Formatter};
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use std::rc::Rc;

use bstr::ByteSlice;
use bstr::{BStr, BString};
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

/// A [`TypeValue`] contains information about the type, and possibly the
/// value of a YARA expression or identifier.
///
/// In the case of primitive types (integer, float, bool and string), the
/// value is optional because the value of expressions and identifiers
/// is unknown at compile time. Structs, arrays and maps always have a
/// reference to a [`Struct`], [`Array`] or [`Map`] respectively, but those
/// structures, arrays and maps don't contain actual values at compile time,
/// they only provide details about the type, like for example, which are
/// the fields in a struct, or what's the type of the items in an array.
#[derive(Clone, Serialize, Deserialize)]
pub enum TypeValue {
    Unknown,
    Integer(Option<i64>),
    Float(Option<f64>),
    Bool(Option<bool>),
    String(Option<BString>),
    Regexp(Option<String>),
    Struct(Rc<Struct>),
    Array(Rc<Array>),
    Map(Rc<Map>),

    // A TypeValue that contains a function is not serialized.
    #[serde(skip)]
    Func(Rc<Func>),
}

macro_rules! gen_boolean_op {
    ($name:ident, $op:tt) => {
        pub fn $name(&self, rhs: &Self) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                _ => {
                    match (self.cast_to_bool(), rhs.cast_to_bool()) {
                        (Self::Bool(Some(lhs)), Self::Bool(Some(rhs))) => {
                             Self::Bool(Some(lhs $op rhs))
                        },
                        _ => {
                             Self::Bool(None)
                        },
                    }
                }
            }
        }
    };
}

macro_rules! gen_arithmetic_op {
    ($name:ident, $op:tt, $checked_op:ident) => {
        pub fn $name(&self, rhs: &Self) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            if let Some(value) = lhs.$checked_op(*rhs) {
                                Self::Integer(Some(value))
                            } else {
                                Self::Integer(None)
                            }
                        }
                        _ => Self::Integer(None)
                    }
                }
                (Self::Integer(lhs), Self::Float(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Float(Some(*lhs as f64 $op rhs))
                        }
                        _ => Self::Float(None)
                    }
                }
                (Self::Float(lhs), Self::Integer(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Float(Some(lhs $op *rhs as f64))
                        }
                        _ => Self::Float(None)
                    }
                }
                (Self::Float(lhs), Self::Float(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Float(Some(lhs $op rhs))
                        }
                        _ => Self::Float(None)
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
                (Self::Integer(lhs), Self::Integer(rhs)) => match (lhs, rhs) {
                    (Some(lhs), Some(rhs)) => {
                        Self::Integer(Some(lhs.$op(rhs)))
                    }
                    _ => Self::Integer(None),
                },
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
                (Self::Integer(lhs), Self::Integer(rhs)) => match (lhs, rhs) {
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
                        Self::Integer(Some(value))
                    }
                    _ => Self::Integer(None),
                },
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
                (Self::String(lhs), Self::String(rhs)) => match (lhs, rhs) {
                    (Some(lhs), Some(rhs)) => {
                        if case_insensitive {
                            let lhs = lhs.to_ascii_lowercase();
                            let rhs = rhs.to_ascii_lowercase();
                            Self::Bool(Some((&lhs).$op(&rhs)))
                        } else {
                            Self::Bool(Some((&lhs).$op(&rhs)))
                        }
                    }
                    _ => Self::Bool(None),
                },
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
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Bool(Some(lhs $op rhs))
                        },
                        _ => Self::Bool(None)
                    }
                }
                (Self::Integer(lhs), Self::Float(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Bool(Some((*lhs as f64) $op *rhs))
                        },
                        _ => Self::Bool(None)
                    }
                }
                (Self::Float(lhs), Self::Integer(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Bool(Some(*lhs $op (*rhs as f64)))
                        },
                        _ => Self::Bool(None)
                    }
                }
                (Self::Float(lhs), Self::Float(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Bool(Some(lhs $op rhs))
                        },
                        _ => Self::Bool(None)
                    }
                }
                (Self::String(lhs), Self::String(rhs)) => {
                    match (lhs, rhs) {
                        (Some(lhs), Some(rhs)) => {
                            Self::Bool(Some(lhs $op rhs))
                        },
                        _ => Self::Bool(None)
                    }
                }
                _ => Self::Unknown,
            }
        }
    };
}

impl TypeValue {
    gen_boolean_op!(and, &&);
    gen_boolean_op!(or, ||);

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

    pub fn has_value(&self) -> bool {
        matches!(
            self,
            Self::Integer(Some(_))
                | Self::Float(Some(_))
                | Self::String(Some(_))
                | Self::Regexp(Some(_))
        )
    }

    pub fn defined(&self) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::Bool(Some(_)) => Self::Bool(Some(true)),
            Self::Integer(Some(_)) => Self::Bool(Some(true)),
            Self::Float(Some(_)) => Self::Bool(Some(true)),
            Self::String(Some(_)) => Self::Bool(Some(true)),
            _ => Self::Bool(None),
        }
    }

    pub fn not(&self) -> Self {
        if let Self::Unknown = self {
            Self::Unknown
        } else {
            match self.cast_to_bool() {
                Self::Bool(Some(b)) => Self::Bool(Some(!b)),
                Self::Bool(None) => Self::Bool(None),
                _ => unreachable!(),
            }
        }
    }

    pub fn bitwise_not(&self) -> Self {
        match self {
            Self::Integer(Some(value)) => Self::Integer(Some(!*value)),
            Self::Integer(None) => Self::Integer(None),
            _ => Self::Unknown,
        }
    }

    pub fn minus(&self) -> Self {
        match self {
            Self::Integer(Some(value)) => Self::Integer(Some(-*value)),
            Self::Float(Some(value)) => Self::Float(Some(-*value)),
            Self::Integer(None) => Self::Integer(None),
            Self::Float(None) => Self::Float(None),
            _ => Self::Unknown,
        }
    }

    pub fn matches(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::String(_), Self::Regexp(_)) => {
                // The result of a `matches` operation is never computed at
                // compile time.
                Self::Bool(None)
            }
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
            Self::Integer(_) => Self::Integer(None),
            Self::Float(_) => Self::Float(None),
            Self::Bool(_) => Self::Bool(None),
            Self::String(_) => Self::String(None),
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
    /// integers, floats, and strings can be casted to bool.
    pub fn cast_to_bool(&self) -> Self {
        match self {
            Self::Integer(Some(i)) => Self::Bool(Some(*i != 0)),
            Self::Float(Some(f)) => Self::Bool(Some(*f != 0.0)),
            Self::String(Some(s)) => Self::Bool(Some(s.len() > 0)),
            Self::Bool(Some(b)) => Self::Bool(Some(*b)),
            Self::Integer(None) => Self::Bool(None),
            Self::Float(None) => Self::Bool(None),
            Self::String(None) => Self::Bool(None),
            Self::Bool(None) => Self::Bool(None),
            _ => panic!("can not cast {:?} to bool", self),
        }
    }

    pub fn as_bstr(&self) -> &BStr {
        if let TypeValue::String(v) = self {
            v.as_ref()
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
        if let TypeValue::Integer(i) = self {
            i.expect("TypeValue doesn't have an associated value")
        } else {
            panic!("called `as_integer` on a TypeValue that is not TypeValue::Integer")
        }
    }

    pub fn as_float(&self) -> f64 {
        if let TypeValue::Float(f) = self {
            f.expect("TypeValue doesn't have an associated value")
        } else {
            panic!("called `as_float` on a TypeValue that is not TypeValue::Float")
        }
    }

    pub fn as_bool(&self) -> bool {
        if let TypeValue::Bool(b) = self {
            b.expect("TypeValue doesn't have an associated value")
        } else {
            panic!(
                "called `as_bool` on a TypeValue that is not TypeValue::Bool"
            )
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
                if let Some(v) = v {
                    write!(f, "boolean({:?})", v)
                } else {
                    write!(f, "boolean(unknown)")
                }
            }
            Self::Integer(v) => {
                if let Some(v) = v {
                    write!(f, "integer({:?})", v)
                } else {
                    write!(f, "integer(unknown)")
                }
            }
            Self::Float(v) => {
                if let Some(v) = v {
                    write!(f, "float({:?})", v)
                } else {
                    write!(f, "float(unknown)")
                }
            }
            Self::String(v) => {
                if let Some(v) = v {
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

impl PartialEq for TypeValue {
    fn eq(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (Self::Unknown, Self::Unknown) => true,
            (Self::Bool(lhs), Self::Bool(rhs)) => lhs == rhs,
            (Self::Integer(lhs), Self::Integer(rhs)) => lhs == rhs,
            (Self::Float(lhs), Self::Float(rhs)) => lhs == rhs,
            (Self::String(lhs), Self::String(rhs)) => lhs == rhs,
            (Self::Integer(Some(lhs)), Self::Float(Some(rhs))) => {
                *lhs as f64 == *rhs
            }
            (Self::Float(Some(lhs)), Self::Integer(Some(rhs))) => {
                *lhs == *rhs as f64
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TypeValue::*;
    use bstr::BString;
    use pretty_assertions::assert_eq;

    #[test]
    fn add() {
        assert_eq!(Unknown.add(&Integer(Some(2))), Unknown);
        assert_eq!(Integer(Some(1)).add(&Unknown), Unknown);
        assert_eq!(Integer(None).add(&Integer(Some(1))), Integer(None));
        assert_eq!(Integer(Some(1)).add(&Integer(None)), Integer(None));
        assert_eq!(Integer(Some(1)).add(&Integer(Some(1))), Integer(Some(2)));
        assert_eq!(Integer(None).add(&Float(Some(1.0))), Float(None));
        assert_eq!(Integer(Some(1)).add(&Float(Some(1.0))), Float(Some(2.0)));
        assert_eq!(Float(Some(1.5)).add(&Float(Some(1.0))), Float(Some(2.5)));
    }

    #[test]
    fn sub() {
        assert_eq!(Unknown.sub(&Integer(Some(2))), Unknown);
        assert_eq!(Integer(Some(1)).sub(&Unknown), Unknown);
        assert_eq!(Integer(None).sub(&Integer(Some(1))), Integer(None));
        assert_eq!(Integer(Some(1)).sub(&Integer(None)), Integer(None));
        assert_eq!(Integer(Some(2)).sub(&Integer(Some(1))), Integer(Some(1)));
        assert_eq!(Integer(Some(2)).sub(&Float(Some(1.0))), Float(Some(1.0)));
        assert_eq!(Float(Some(1.5)).sub(&Float(Some(1.0))), Float(Some(0.5)));
    }

    #[test]
    fn mul() {
        assert_eq!(Unknown.mul(&Integer(Some(2))), Unknown);
        assert_eq!(Integer(Some(1)).mul(&Unknown), Unknown);
        assert_eq!(Integer(None).mul(&Integer(Some(1))), Integer(None));
        assert_eq!(Integer(Some(1)).mul(&Integer(None)), Integer(None));
        assert_eq!(Integer(Some(2)).mul(&Integer(Some(2))), Integer(Some(4)));
        assert_eq!(Integer(Some(2)).mul(&Float(Some(2.0))), Float(Some(4.0)));
        assert_eq!(Float(Some(1.5)).mul(&Float(Some(2.0))), Float(Some(3.0)));
    }

    #[test]
    fn div() {
        assert_eq!(Unknown.div(&Integer(Some(2))), Unknown);
        assert_eq!(Integer(Some(1)).div(&Unknown), Unknown);
        assert_eq!(Integer(None).div(&Integer(Some(1))), Integer(None));
        assert_eq!(Integer(Some(1)).div(&Integer(None)), Integer(None));
        assert_eq!(Integer(Some(2)).div(&Integer(Some(2))), Integer(Some(1)));
        assert_eq!(Integer(Some(2)).div(&Float(Some(2.0))), Float(Some(1.0)));
        assert_eq!(Float(Some(3.0)).div(&Float(Some(2.0))), Float(Some(1.5)));
        assert_eq!(Integer(Some(2)).div(&Integer(Some(0))), Integer(None));
        assert_eq!(
            Float(Some(2.0)).div(&Float(Some(0.0))),
            Float(Some(f64::INFINITY))
        );
        assert_eq!(
            Integer(Some(2)).div(&Float(Some(0.0))),
            Float(Some(f64::INFINITY))
        );
    }

    #[test]
    fn rem() {
        assert_eq!(Unknown.rem(&Integer(Some(2))), Unknown);
        assert_eq!(Integer(Some(1)).rem(&Unknown), Unknown);
        assert_eq!(Integer(None).rem(&Integer(Some(1))), Integer(None));
        assert_eq!(Integer(Some(1)).rem(&Integer(None)), Integer(None));
        assert_eq!(Integer(Some(3)).rem(&Integer(Some(2))), Integer(Some(1)));
        assert_eq!(Integer(Some(5)).rem(&Float(Some(2.0))), Float(Some(1.0)));
        assert_eq!(Float(Some(3.0)).rem(&Float(Some(2.0))), Float(Some(1.0)));
        assert_eq!(Integer(Some(2)).rem(&Integer(Some(0))), Integer(None));
    }

    #[test]
    fn and() {
        assert_eq!(Unknown.and(&Bool(Some(true))), Unknown);
        assert_eq!(Bool(Some(true)).and(&Unknown), Unknown);
        assert_eq!(Bool(Some(true)).and(&Bool(None)), Bool(None));
        assert_eq!(Bool(None).and(&Bool(Some(true))), Bool(None));

        assert_eq!(
            Bool(Some(true)).and(&Bool(Some(false))),
            Bool(Some(false))
        );

        assert_eq!(Bool(Some(true)).and(&Bool(Some(true))), Bool(Some(true)));
        assert_eq!(Integer(Some(1)).and(&Bool(Some(true))), Bool(Some(true)));
        assert_eq!(Integer(Some(0)).and(&Bool(Some(true))), Bool(Some(false)));

        assert_eq!(
            Integer(Some(1)).and(&String(Some(BString::from("foo")))),
            Bool(Some(true))
        );

        assert_eq!(Float(Some(1.0)).and(&Float(Some(2.0))), Bool(Some(true)));
        assert_eq!(Float(Some(0.0)).and(&Float(Some(2.0))), Bool(Some(false)));
    }

    #[test]
    fn shl() {
        assert_eq!(Unknown.shl(&Bool(Some(true))), Unknown);
        assert_eq!(Bool(Some(true)).shl(&Unknown), Unknown);
        assert_eq!(Integer(None).shl(&Integer(Some(1))), Integer(None));
        assert_eq!(Integer(Some(1)).shl(&Integer(None)), Integer(None));
        assert_eq!(Integer(Some(4)).shl(&Integer(Some(1))), Integer(Some(8)));
        assert_eq!(Integer(Some(1)).shl(&Integer(Some(64))), Integer(Some(0)));
    }

    #[test]
    fn shr() {
        assert_eq!(Unknown.shr(&Bool(Some(true))), Unknown);
        assert_eq!(Bool(Some(true)).shr(&Unknown), Unknown);
        assert_eq!(Integer(None).shr(&Integer(Some(1))), Integer(None));
        assert_eq!(Integer(Some(1)).shr(&Integer(None)), Integer(None));
        assert_eq!(Integer(Some(1)).shr(&Integer(Some(1))), Integer(Some(0)));
        assert_eq!(Integer(Some(2)).shr(&Integer(Some(1))), Integer(Some(1)));
    }

    #[test]
    fn defined() {
        assert_eq!(Unknown.defined(), Unknown);
        assert_eq!(Bool(Some(true)).defined(), Bool(Some(true)));
        assert_eq!(Bool(Some(false)).defined(), Bool(Some(true)));
        assert_eq!(Integer(Some(0)).defined(), Bool(Some(true)));
        assert_eq!(Float(Some(0.0)).defined(), Bool(Some(true)));

        assert_eq!(
            String(Some(BString::from(""))).defined(),
            Bool(Some(true))
        );
    }
}
