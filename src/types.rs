use std::fmt::{Debug, Formatter};
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use std::sync::Arc;

use bstr::{BString, ByteSlice};

use crate::symbols::{SymbolIndex, SymbolLookup};

/// Type of a YARA expression or identifier.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Type {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Struct,
    Array(ArrayItemType),
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ArrayItemType {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Struct,
}

/// Value of a YARA expression or identifier.
#[derive(Clone)]
pub enum Value {
    Unknown,
    Integer(i64),
    Float(f64),
    Bool(bool),
    String(BString),
    Struct(Arc<dyn SymbolLookup + Send + Sync>),
    Array(Arc<dyn SymbolIndex + Send + Sync>),
}

macro_rules! cast_to_bool {
    ($value:expr) => {{
        match $value {
            Value::Integer(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::String(s) => s.len() > 0,
            Value::Bool(b) => *b,
            _ => panic!("can not cast {:?} to bool", $value),
        }
    }};
}

macro_rules! gen_boolean_op {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown)=> Self::Unknown,
                (Self::Struct(_), _) | (_, Self::Struct(_)) => {
                    panic!(
                        "unsupported `{}` operation for {:?} and {:?}",
                        stringify!($name), self, rhs)
                }
                _ => {
                    let lhs = cast_to_bool!(self);
                    let rhs = cast_to_bool!(rhs);

                    Self::Bool(lhs $op rhs)
                }
            }
        }
    };
}

macro_rules! gen_arithmetic_op {
    ($name:ident, $op:tt, $checked_op:ident) => {
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown)=> Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
                    if let Some(value) = lhs.$checked_op(*rhs) {
                        Self::Integer(value)
                    } else {
                        Self::Unknown
                    }
                }
                (Self::Integer(lhs), Self::Float(rhs)) => {
                    Self::Float(*lhs as f64 $op rhs)
                }
                (Self::Float(lhs), Self::Integer(rhs)) => {
                    Self::Float(lhs $op *rhs as f64)
                }
                (Self::Float(lhs), Self::Float(rhs)) => {
                    Self::Float(lhs $op rhs)
                }
                _ => panic!(
                    "unsupported `{}` operation for {:?} and {:?}",
                    stringify!($name), self, rhs
                ),
            }
        }
    };
}

macro_rules! gen_bitwise_op {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
                    Self::Integer(lhs.$op(rhs))
                }
                _ => panic!(
                    "unsupported `{}` operation for {:?} and {:?}",
                    stringify!($name),
                    self,
                    rhs
                ),
            }
        }
    };
}

macro_rules! gen_shift_op {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => {
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

                    Self::Integer(value)
                }
                _ => panic!(
                    "unsupported `{}` operation for {:?} and {:?}",
                    stringify!($name),
                    self,
                    rhs
                ),
            }
        }
    };
}

macro_rules! gen_string_op {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(
            &self,
            rhs: &Value,
            case_insensitive: bool,
        ) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::String(lhs), Self::String(rhs)) => {
                    if case_insensitive {
                        let lhs = lhs.to_ascii_lowercase();
                        let rhs = rhs.to_ascii_lowercase();
                        Value::Bool((&lhs).$op(&rhs))
                    } else {
                        Value::Bool((&lhs).$op(&rhs))
                    }
                }
                _ => panic!(
                    "unsupported `{}` operation for {:?} and {:?}",
                    stringify!($name),
                    self,
                    rhs
                ),
            }
        }
    };
}

macro_rules! gen_comparison_op {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::Integer(lhs), Self::Integer(rhs)) => Value::Bool(lhs $op rhs),
                (Self::Integer(lhs), Self::Float(rhs)) => Value::Bool((*lhs as f64) $op *rhs),
                (Self::Float(lhs), Self::Integer(rhs)) => Value::Bool(*lhs $op (*rhs as f64)),
                (Self::Float(lhs), Self::Float(rhs)) => Value::Bool(lhs $op rhs),
                (Self::String(lhs), Self::String(rhs)) => Value::Bool(lhs $op rhs),
                _ => panic!(
                    "unsupported `{}` operation for {:?} and {:?}",
                    stringify!($name),
                    self,
                    rhs
                ),
            }
        }
    };
}

impl Value {
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
}

pub(crate) struct TypeValue(pub Type, pub Option<Value>);

/// Compares two YARA values.
///
/// They are equal if they have the same type and value. Comparing
/// two structures or arrays causes a panic.
impl PartialEq for Value {
    fn eq(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (Self::Unknown, Self::Unknown) => true,
            (Self::Bool(lhs), Self::Bool(rhs)) => lhs == rhs,
            (Self::Integer(lhs), Self::Integer(rhs)) => lhs == rhs,
            (Self::Float(lhs), Self::Float(rhs)) => lhs == rhs,
            (Self::Integer(lhs), Self::Float(rhs)) => *lhs as f64 == *rhs,
            (Self::Float(lhs), Self::Integer(rhs)) => *lhs == *rhs as f64,
            (Self::String(lhs), Self::String(rhs)) => lhs == rhs,
            (Self::Struct(_), Self::Struct(_)) => {
                panic!("can't compare two structures")
            }
            (Self::Array(_), Self::Array(_)) => {
                panic!("can't compare two arrays")
            }
            _ => false,
        }
    }
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Bool(v) => write!(f, "Bool({:?})", v),
            Self::Integer(v) => write!(f, "Integer({:?})", v),
            Self::Float(v) => write!(f, "Float({:?})", v),
            Self::String(v) => write!(f, "String({:?})", v),
            Self::Struct(_) => write!(f, "Struct"),
            Self::Array(_) => write!(f, "Array"),
        }
    }
}

impl From<ArrayItemType> for Type {
    fn from(array_item_ty: ArrayItemType) -> Self {
        match array_item_ty {
            ArrayItemType::Unknown => Self::Unknown,
            ArrayItemType::Integer => Self::Integer,
            ArrayItemType::Float => Self::Float,
            ArrayItemType::Bool => Self::Bool,
            ArrayItemType::String => Self::String,
            ArrayItemType::Struct => Self::Struct,
        }
    }
}

impl From<Type> for ArrayItemType {
    fn from(ty: Type) -> Self {
        match ty {
            Type::Unknown => Self::Unknown,
            Type::Integer => Self::Integer,
            Type::Float => Self::Float,
            Type::Bool => Self::Bool,
            Type::String => Self::String,
            Type::Struct => Self::Struct,
            Type::Array(_) => panic!("array of arrays are not supported"),
        }
    }
}

impl From<Value> for i64 {
    fn from(value: Value) -> Self {
        if let Value::Integer(value) = value {
            value
        } else {
            panic!("can not convert into i64")
        }
    }
}

impl From<Value> for f64 {
    fn from(value: Value) -> Self {
        if let Value::Float(value) = value {
            value
        } else {
            panic!("can not convert into f64")
        }
    }
}

impl From<Value> for bool {
    fn from(value: Value) -> Self {
        if let Value::Bool(value) = value {
            value
        } else {
            panic!("can not convert into bool")
        }
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Self::Float(value as f64)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(BString::from(value))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Value;
    use bstr::BString;
    use pretty_assertions::assert_eq;

    #[test]
    fn value_add() {
        assert_eq!(Value::Unknown.add(&Value::Integer(2)), Value::Unknown);
        assert_eq!(Value::Integer(1).add(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Integer(1).add(&Value::Integer(1)),
            Value::Integer(2)
        );

        assert_eq!(
            Value::Integer(1).add(&Value::Float(1.0)),
            Value::Float(2.0)
        );

        assert_eq!(
            Value::Float(1.5).add(&Value::Float(1.0)),
            Value::Float(2.5)
        );
    }

    #[test]
    fn value_sub() {
        assert_eq!(Value::Unknown.sub(&Value::Integer(2)), Value::Unknown);
        assert_eq!(Value::Integer(1).sub(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Integer(2).sub(&Value::Integer(1)),
            Value::Integer(1)
        );

        assert_eq!(
            Value::Integer(2).sub(&Value::Float(1.0)),
            Value::Float(1.0)
        );

        assert_eq!(
            Value::Float(1.5).sub(&Value::Float(1.0)),
            Value::Float(0.5)
        );
    }

    #[test]
    fn value_mul() {
        assert_eq!(Value::Unknown.mul(&Value::Integer(2)), Value::Unknown);
        assert_eq!(Value::Integer(1).mul(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Integer(2).mul(&Value::Integer(2)),
            Value::Integer(4)
        );

        assert_eq!(
            Value::Integer(2).mul(&Value::Float(2.0)),
            Value::Float(4.0)
        );

        assert_eq!(
            Value::Float(1.5).mul(&Value::Float(2.0)),
            Value::Float(3.0)
        );
    }

    #[test]
    fn value_div() {
        assert_eq!(Value::Unknown.div(&Value::Integer(2)), Value::Unknown);
        assert_eq!(Value::Integer(1).div(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Integer(2).div(&Value::Integer(2)),
            Value::Integer(1)
        );

        assert_eq!(
            Value::Integer(2).div(&Value::Float(2.0)),
            Value::Float(1.0)
        );

        assert_eq!(
            Value::Float(3.0).div(&Value::Float(2.0)),
            Value::Float(1.5)
        );

        assert_eq!(Value::Integer(2).div(&Value::Integer(0)), Value::Unknown);

        assert_eq!(
            Value::Float(2.0).div(&Value::Float(0.0)),
            Value::Float(f64::INFINITY)
        );

        assert_eq!(
            Value::Integer(2).div(&Value::Float(0.0)),
            Value::Float(f64::INFINITY)
        );
    }

    #[test]
    fn value_rem() {
        assert_eq!(Value::Unknown.rem(&Value::Integer(2)), Value::Unknown);
        assert_eq!(Value::Integer(1).rem(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Integer(3).rem(&Value::Integer(2)),
            Value::Integer(1)
        );

        assert_eq!(
            Value::Integer(5).rem(&Value::Float(2.0)),
            Value::Float(1.0)
        );

        assert_eq!(
            Value::Float(3.0).rem(&Value::Float(2.0)),
            Value::Float(1.0)
        );

        assert_eq!(Value::Integer(2).rem(&Value::Integer(0)), Value::Unknown);
    }

    #[test]
    fn value_and() {
        assert_eq!(Value::Unknown.and(&Value::Bool(true)), Value::Unknown);
        assert_eq!(Value::Bool(true).and(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Bool(true).and(&Value::Bool(false)),
            Value::Bool(false)
        );

        assert_eq!(
            Value::Bool(true).and(&Value::Bool(true)),
            Value::Bool(true)
        );

        assert_eq!(
            Value::Integer(1).and(&Value::Bool(true)),
            Value::Bool(true)
        );

        assert_eq!(
            Value::Integer(0).and(&Value::Bool(true)),
            Value::Bool(false)
        );

        assert_eq!(
            Value::Integer(1).and(&Value::String(BString::from("foo"))),
            Value::Bool(true)
        );

        assert_eq!(
            Value::Float(1.0).and(&Value::Float(2.0)),
            Value::Bool(true)
        );

        assert_eq!(
            Value::Float(0.0).and(&Value::Float(2.0)),
            Value::Bool(false)
        );
    }

    #[test]
    fn value_shl() {
        assert_eq!(Value::Unknown.shl(&Value::Bool(true)), Value::Unknown);
        assert_eq!(Value::Bool(true).shl(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Integer(4).shl(&Value::Integer(1)),
            Value::Integer(8)
        );

        assert_eq!(
            Value::Integer(1).shl(&Value::Integer(64)),
            Value::Integer(0)
        );
    }

    #[test]
    fn value_shr() {
        assert_eq!(Value::Unknown.shr(&Value::Bool(true)), Value::Unknown);
        assert_eq!(Value::Bool(true).shr(&Value::Unknown), Value::Unknown);

        assert_eq!(
            Value::Integer(1).shr(&Value::Integer(1)),
            Value::Integer(0)
        );

        assert_eq!(
            Value::Integer(2).shr(&Value::Integer(1)),
            Value::Integer(1)
        );
    }
}
