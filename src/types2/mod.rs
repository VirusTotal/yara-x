use std::fmt::{Debug, Display, Formatter};
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use std::rc::Rc;

use bstr::BString;
use bstr::ByteSlice;

mod array;
mod map;
mod structure;

pub use array::*;
pub use map::*;
pub use structure::*;

#[derive(Clone, Copy, PartialEq)]
pub enum Type {
    Unknown,
    Integer,
    Float,
    Bool,
    String,
    Struct,
    Array,
    Map,
}

#[derive(Clone)]
pub enum Value {
    Unknown,
    Integer(Option<i64>),
    Float(Option<f64>),
    Bool(Option<bool>),
    String(Option<BString>),
    Struct(Rc<Struct>),
    Array(Rc<Array>),
    Map(Rc<Map>),
}

macro_rules! cast_to_bool {
    ($value:expr) => {{
        match $value {
            Value::Integer(Some(i)) => *i != 0,
            Value::Float(Some(f)) => *f != 0.0,
            Value::String(Some(s)) => s.len() > 0,
            Value::Bool(Some(b)) => *b,
            _ => panic!("can not cast {:?} to bool", $value),
        }
    }};
}

macro_rules! gen_boolean_op {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown)=> Self::Unknown,
                _ => {
                    let lhs = cast_to_bool!(self);
                    let rhs = cast_to_bool!(rhs);

                    Self::Bool(Some(lhs $op rhs))
                }
            }
        }
    };
}

macro_rules! gen_arithmetic_op {
    ($name:ident, $op:tt, $checked_op:ident) => {
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
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
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
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
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
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
        pub(crate) fn $name(
            &self,
            rhs: &Value,
            case_insensitive: bool,
        ) -> Value {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                (Self::String(lhs), Self::String(rhs)) => match (lhs, rhs) {
                    (Some(lhs), Some(rhs)) => {
                        if case_insensitive {
                            let lhs = lhs.to_ascii_lowercase();
                            let rhs = rhs.to_ascii_lowercase();
                            Value::Bool(Some((&lhs).$op(&rhs)))
                        } else {
                            Value::Bool(Some((&lhs).$op(&rhs)))
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
        pub(crate) fn $name(&self, rhs: &Value) -> Value {
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
    gen_comparison_op!(ne, !=);

    pub(crate) fn not(&self) -> Value {
        if let Value::Unknown = self {
            Value::Unknown
        } else {
            Value::Bool(Some(!cast_to_bool!(self)))
        }
    }

    pub(crate) fn bitwise_not(&self) -> Value {
        match self {
            Value::Integer(Some(value)) => Value::Integer(Some(!*value)),
            _ => Value::Unknown,
        }
    }

    pub(crate) fn minus(&self) -> Value {
        match self {
            Value::Integer(Some(value)) => Value::Integer(Some(-*value)),
            Value::Float(Some(value)) => Value::Float(Some(-*value)),
            _ => Value::Unknown,
        }
    }

    pub(crate) fn ty(&self) -> Type {
        match self {
            Value::Unknown => Type::Unknown,
            Value::Integer(_) => Type::Integer,
            Value::Float(_) => Type::Float,
            Value::Bool(_) => Type::Bool,
            Value::String(_) => Type::String,
            Value::Map(_) => Type::Map,
            Value::Struct(_) => Type::Struct,
            Value::Array(_) => Type::Array,
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Bool(v) => write!(f, "boolean({:?})", v),
            Self::Integer(v) => write!(f, "integer({:?})", v),
            Self::Float(v) => write!(f, "float({:?})", v),
            Self::String(v) => write!(f, "string({:?})", v),
            Self::Map(_) => write!(f, "map"),
            Self::Struct(_) => write!(f, "struct"),
            Self::Array(_) => write!(f, "array"),
        }
    }
}

impl PartialEq for Value {
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
    use super::Value;
    use bstr::BString;
    use pretty_assertions::assert_eq;

    #[test]
    fn value_add() {
        assert_eq!(
            Value::Unknown.add(&Value::Integer(Some(2))),
            Value::Unknown
        );
        assert_eq!(
            Value::Integer(Some(1)).add(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(None).add(&Value::Integer(Some(1))),
            Value::Integer(None)
        );

        assert_eq!(
            Value::Integer(Some(1)).add(&Value::Integer(None)),
            Value::Integer(None)
        );

        assert_eq!(
            Value::Integer(Some(1)).add(&Value::Integer(Some(1))),
            Value::Integer(Some(2))
        );

        assert_eq!(
            Value::Integer(None).add(&Value::Float(Some(1.0))),
            Value::Float(None)
        );

        assert_eq!(
            Value::Integer(Some(1)).add(&Value::Float(Some(1.0))),
            Value::Float(Some(2.0))
        );

        assert_eq!(
            Value::Float(Some(1.5)).add(&Value::Float(Some(1.0))),
            Value::Float(Some(2.5))
        );
    }

    #[test]
    fn value_sub() {
        assert_eq!(
            Value::Unknown.sub(&Value::Integer(Some(2))),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(Some(1)).sub(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(None).sub(&Value::Integer(Some(1))),
            Value::Integer(None)
        );

        assert_eq!(
            Value::Integer(Some(1)).sub(&Value::Integer(None)),
            Value::Integer(None)
        );

        assert_eq!(
            Value::Integer(Some(2)).sub(&Value::Integer(Some(1))),
            Value::Integer(Some(1))
        );

        assert_eq!(
            Value::Integer(Some(2)).sub(&Value::Float(Some(1.0))),
            Value::Float(Some(1.0))
        );

        assert_eq!(
            Value::Float(Some(1.5)).sub(&Value::Float(Some(1.0))),
            Value::Float(Some(0.5))
        );
    }

    #[test]
    fn value_mul() {
        assert_eq!(
            Value::Unknown.mul(&Value::Integer(Some(2))),
            Value::Unknown
        );
        assert_eq!(
            Value::Integer(Some(1)).mul(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(Some(2)).mul(&Value::Integer(Some(2))),
            Value::Integer(Some(4))
        );

        assert_eq!(
            Value::Integer(Some(2)).mul(&Value::Float(Some(2.0))),
            Value::Float(Some(4.0))
        );

        assert_eq!(
            Value::Float(Some(1.5)).mul(&Value::Float(Some(2.0))),
            Value::Float(Some(3.0))
        );
    }

    #[test]
    fn value_div() {
        assert_eq!(
            Value::Unknown.div(&Value::Integer(Some(2))),
            Value::Unknown
        );
        assert_eq!(
            Value::Integer(Some(1)).div(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(Some(2)).div(&Value::Integer(Some(2))),
            Value::Integer(Some(1))
        );

        assert_eq!(
            Value::Integer(Some(2)).div(&Value::Float(Some(2.0))),
            Value::Float(Some(1.0))
        );

        assert_eq!(
            Value::Float(Some(3.0)).div(&Value::Float(Some(2.0))),
            Value::Float(Some(1.5))
        );

        assert_eq!(
            Value::Integer(Some(2)).div(&Value::Integer(Some(0))),
            Value::Integer(None)
        );

        assert_eq!(
            Value::Float(Some(2.0)).div(&Value::Float(Some(0.0))),
            Value::Float(Some(f64::INFINITY))
        );

        assert_eq!(
            Value::Integer(Some(2)).div(&Value::Float(Some(0.0))),
            Value::Float(Some(f64::INFINITY))
        );
    }

    #[test]
    fn value_rem() {
        assert_eq!(
            Value::Unknown.rem(&Value::Integer(Some(2))),
            Value::Unknown
        );
        assert_eq!(
            Value::Integer(Some(1)).rem(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(Some(3)).rem(&Value::Integer(Some(2))),
            Value::Integer(Some(1))
        );

        assert_eq!(
            Value::Integer(Some(5)).rem(&Value::Float(Some(2.0))),
            Value::Float(Some(1.0))
        );

        assert_eq!(
            Value::Float(Some(3.0)).rem(&Value::Float(Some(2.0))),
            Value::Float(Some(1.0))
        );

        assert_eq!(
            Value::Integer(Some(2)).rem(&Value::Integer(Some(0))),
            Value::Integer(None)
        );
    }

    #[test]
    fn value_and() {
        assert_eq!(
            Value::Unknown.and(&Value::Bool(Some(true))),
            Value::Unknown
        );
        assert_eq!(
            Value::Bool(Some(true)).and(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Bool(Some(true)).and(&Value::Bool(Some(false))),
            Value::Bool(Some(false))
        );

        assert_eq!(
            Value::Bool(Some(true)).and(&Value::Bool(Some(true))),
            Value::Bool(Some(true))
        );

        assert_eq!(
            Value::Integer(Some(1)).and(&Value::Bool(Some(true))),
            Value::Bool(Some(true))
        );

        assert_eq!(
            Value::Integer(Some(0)).and(&Value::Bool(Some(true))),
            Value::Bool(Some(false))
        );

        assert_eq!(
            Value::Integer(Some(1))
                .and(&Value::String(Some(BString::from("foo")))),
            Value::Bool(Some(true))
        );

        assert_eq!(
            Value::Float(Some(1.0)).and(&Value::Float(Some(2.0))),
            Value::Bool(Some(true))
        );

        assert_eq!(
            Value::Float(Some(0.0)).and(&Value::Float(Some(2.0))),
            Value::Bool(Some(false))
        );
    }

    #[test]
    fn value_shl() {
        assert_eq!(
            Value::Unknown.shl(&Value::Bool(Some(true))),
            Value::Unknown
        );
        assert_eq!(
            Value::Bool(Some(true)).shl(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(Some(4)).shl(&Value::Integer(Some(1))),
            Value::Integer(Some(8))
        );

        assert_eq!(
            Value::Integer(Some(1)).shl(&Value::Integer(Some(64))),
            Value::Integer(Some(0))
        );
    }

    #[test]
    fn value_shr() {
        assert_eq!(
            Value::Unknown.shr(&Value::Bool(Some(true))),
            Value::Unknown
        );
        assert_eq!(
            Value::Bool(Some(true)).shr(&Value::Unknown),
            Value::Unknown
        );

        assert_eq!(
            Value::Integer(Some(1)).shr(&Value::Integer(Some(1))),
            Value::Integer(Some(0))
        );

        assert_eq!(
            Value::Integer(Some(2)).shr(&Value::Integer(Some(1))),
            Value::Integer(Some(1))
        );
    }
}
