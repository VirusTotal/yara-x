use std::fmt::{Debug, Display, Formatter};
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use std::rc::Rc;

use bstr::ByteSlice;
use bstr::{BStr, BString};

mod array;
mod map;
mod structure;

pub use array::*;
pub use map::*;
pub use structure::*;

#[derive(Clone, PartialEq)]
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
            Self::Struct => write!(f, "struct"),
            Self::Array => write!(f, "array"),
            Self::Map => write!(f, "map"),
        }
    }
}

pub(crate) const UNKNOWN: TypeValue = TypeValue::Unknown;
pub(crate) const UNKNOWN_BOOL: TypeValue = TypeValue::Bool(None);
pub(crate) const UNKNOWN_INT: TypeValue = TypeValue::Integer(None);
pub(crate) const FALSE: TypeValue = TypeValue::Bool(Some(false));
pub(crate) const TRUE: TypeValue = TypeValue::Bool(Some(true));

#[derive(Clone)]
pub enum TypeValue {
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
            TypeValue::Integer(Some(i)) => TypeValue::Bool(Some(*i != 0)),
            TypeValue::Float(Some(f)) => TypeValue::Bool(Some(*f != 0.0)),
            TypeValue::String(Some(s)) => TypeValue::Bool(Some(s.len() > 0)),
            TypeValue::Bool(Some(b)) => TypeValue::Bool(Some(*b)),
            TypeValue::Integer(None) => TypeValue::Bool(None),
            TypeValue::Float(None) => TypeValue::Bool(None),
            TypeValue::String(None) => TypeValue::Bool(None),
            TypeValue::Bool(None) => TypeValue::Bool(None),
            _ => panic!("can not cast {:?} to bool", $value),
        }
    }};
}

macro_rules! gen_boolean_op {
    ($name:ident, $op:tt) => {
        pub(crate) fn $name(&self, rhs: &Self) -> Self {
            match (self, rhs) {
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                _ => {
                    let lhs = cast_to_bool!(self);
                    let rhs = cast_to_bool!(rhs);
                    match (lhs, rhs) {
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
        pub(crate) fn $name(&self, rhs: &Self) -> Self {
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
        pub(crate) fn $name(&self, rhs: &Self) -> Self {
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
        pub(crate) fn $name(&self, rhs: &Self) -> Self {
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
            rhs: &Self,
            case_insensitive: bool,
        ) -> Self {
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
        pub(crate) fn $name(&self, rhs: &Self) -> Self {
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

    pub(crate) fn not(&self) -> Self {
        if let Self::Unknown = self {
            Self::Unknown
        } else {
            match cast_to_bool!(self) {
                Self::Bool(Some(b)) => Self::Bool(Some(!b)),
                Self::Bool(None) => Self::Bool(None),
                _ => unreachable!(),
            }
        }
    }

    pub(crate) fn bitwise_not(&self) -> Self {
        match self {
            Self::Integer(Some(value)) => Self::Integer(Some(!*value)),
            _ => Self::Unknown,
        }
    }

    pub(crate) fn minus(&self) -> Self {
        match self {
            Self::Integer(Some(value)) => Self::Integer(Some(-*value)),
            Self::Float(Some(value)) => Self::Float(Some(-*value)),
            _ => Self::Unknown,
        }
    }

    pub(crate) fn ty(&self) -> Type {
        match self {
            Self::Unknown => Type::Unknown,
            Self::Integer(_) => Type::Integer,
            Self::Float(_) => Type::Float,
            Self::Bool(_) => Type::Bool,
            Self::String(_) => Type::String,
            Self::Map(_) => Type::Map,
            Self::Struct(_) => Type::Struct,
            Self::Array(_) => Type::Array,
        }
    }

    pub fn as_bstr(&self) -> Option<&BStr> {
        if let TypeValue::String(v) = self {
            v.as_ref().map(|v| v.as_bstr())
        } else {
            None
        }
    }

    pub fn as_array(&self) -> Option<Rc<Array>> {
        if let TypeValue::Array(array) = self {
            Some(array.clone())
        } else {
            None
        }
    }

    pub fn as_struct(&self) -> Option<Rc<Struct>> {
        if let TypeValue::Struct(structure) = self {
            Some(structure.clone())
        } else {
            None
        }
    }
}

impl From<&Type> for TypeValue {
    fn from(ty: &Type) -> Self {
        match ty {
            Type::Unknown => Self::Unknown,
            Type::Integer => Self::Integer(None),
            Type::Float => Self::Float(None),
            Type::Bool => Self::Bool(None),
            Type::String => Self::String(None),
            Type::Struct => todo!(),
            Type::Array => todo!(),
            Type::Map => todo!(),
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
            Self::Map(_) => write!(f, "map"),
            Self::Struct(_) => write!(f, "struct"),
            Self::Array(_) => write!(f, "array"),
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
    use super::TypeValue;
    use bstr::BString;
    use pretty_assertions::assert_eq;

    #[test]
    fn value_add() {
        assert_eq!(
            TypeValue::Unknown.add(&TypeValue::Integer(Some(2))),
            TypeValue::Unknown
        );
        assert_eq!(
            TypeValue::Integer(Some(1)).add(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(None).add(&TypeValue::Integer(Some(1))),
            TypeValue::Integer(None)
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).add(&TypeValue::Integer(None)),
            TypeValue::Integer(None)
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).add(&TypeValue::Integer(Some(1))),
            TypeValue::Integer(Some(2))
        );

        assert_eq!(
            TypeValue::Integer(None).add(&TypeValue::Float(Some(1.0))),
            TypeValue::Float(None)
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).add(&TypeValue::Float(Some(1.0))),
            TypeValue::Float(Some(2.0))
        );

        assert_eq!(
            TypeValue::Float(Some(1.5)).add(&TypeValue::Float(Some(1.0))),
            TypeValue::Float(Some(2.5))
        );
    }

    #[test]
    fn value_sub() {
        assert_eq!(
            TypeValue::Unknown.sub(&TypeValue::Integer(Some(2))),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).sub(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(None).sub(&TypeValue::Integer(Some(1))),
            TypeValue::Integer(None)
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).sub(&TypeValue::Integer(None)),
            TypeValue::Integer(None)
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).sub(&TypeValue::Integer(Some(1))),
            TypeValue::Integer(Some(1))
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).sub(&TypeValue::Float(Some(1.0))),
            TypeValue::Float(Some(1.0))
        );

        assert_eq!(
            TypeValue::Float(Some(1.5)).sub(&TypeValue::Float(Some(1.0))),
            TypeValue::Float(Some(0.5))
        );
    }

    #[test]
    fn value_mul() {
        assert_eq!(
            TypeValue::Unknown.mul(&TypeValue::Integer(Some(2))),
            TypeValue::Unknown
        );
        assert_eq!(
            TypeValue::Integer(Some(1)).mul(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).mul(&TypeValue::Integer(Some(2))),
            TypeValue::Integer(Some(4))
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).mul(&TypeValue::Float(Some(2.0))),
            TypeValue::Float(Some(4.0))
        );

        assert_eq!(
            TypeValue::Float(Some(1.5)).mul(&TypeValue::Float(Some(2.0))),
            TypeValue::Float(Some(3.0))
        );
    }

    #[test]
    fn value_div() {
        assert_eq!(
            TypeValue::Unknown.div(&TypeValue::Integer(Some(2))),
            TypeValue::Unknown
        );
        assert_eq!(
            TypeValue::Integer(Some(1)).div(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).div(&TypeValue::Integer(Some(2))),
            TypeValue::Integer(Some(1))
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).div(&TypeValue::Float(Some(2.0))),
            TypeValue::Float(Some(1.0))
        );

        assert_eq!(
            TypeValue::Float(Some(3.0)).div(&TypeValue::Float(Some(2.0))),
            TypeValue::Float(Some(1.5))
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).div(&TypeValue::Integer(Some(0))),
            TypeValue::Integer(None)
        );

        assert_eq!(
            TypeValue::Float(Some(2.0)).div(&TypeValue::Float(Some(0.0))),
            TypeValue::Float(Some(f64::INFINITY))
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).div(&TypeValue::Float(Some(0.0))),
            TypeValue::Float(Some(f64::INFINITY))
        );
    }

    #[test]
    fn value_rem() {
        assert_eq!(
            TypeValue::Unknown.rem(&TypeValue::Integer(Some(2))),
            TypeValue::Unknown
        );
        assert_eq!(
            TypeValue::Integer(Some(1)).rem(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(Some(3)).rem(&TypeValue::Integer(Some(2))),
            TypeValue::Integer(Some(1))
        );

        assert_eq!(
            TypeValue::Integer(Some(5)).rem(&TypeValue::Float(Some(2.0))),
            TypeValue::Float(Some(1.0))
        );

        assert_eq!(
            TypeValue::Float(Some(3.0)).rem(&TypeValue::Float(Some(2.0))),
            TypeValue::Float(Some(1.0))
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).rem(&TypeValue::Integer(Some(0))),
            TypeValue::Integer(None)
        );
    }

    #[test]
    fn value_and() {
        assert_eq!(
            TypeValue::Unknown.and(&TypeValue::Bool(Some(true))),
            TypeValue::Unknown
        );
        assert_eq!(
            TypeValue::Bool(Some(true)).and(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Bool(Some(true)).and(&TypeValue::Bool(Some(false))),
            TypeValue::Bool(Some(false))
        );

        assert_eq!(
            TypeValue::Bool(Some(true)).and(&TypeValue::Bool(Some(true))),
            TypeValue::Bool(Some(true))
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).and(&TypeValue::Bool(Some(true))),
            TypeValue::Bool(Some(true))
        );

        assert_eq!(
            TypeValue::Integer(Some(0)).and(&TypeValue::Bool(Some(true))),
            TypeValue::Bool(Some(false))
        );

        assert_eq!(
            TypeValue::Integer(Some(1))
                .and(&TypeValue::String(Some(BString::from("foo")))),
            TypeValue::Bool(Some(true))
        );

        assert_eq!(
            TypeValue::Float(Some(1.0)).and(&TypeValue::Float(Some(2.0))),
            TypeValue::Bool(Some(true))
        );

        assert_eq!(
            TypeValue::Float(Some(0.0)).and(&TypeValue::Float(Some(2.0))),
            TypeValue::Bool(Some(false))
        );
    }

    #[test]
    fn value_shl() {
        assert_eq!(
            TypeValue::Unknown.shl(&TypeValue::Bool(Some(true))),
            TypeValue::Unknown
        );
        assert_eq!(
            TypeValue::Bool(Some(true)).shl(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(Some(4)).shl(&TypeValue::Integer(Some(1))),
            TypeValue::Integer(Some(8))
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).shl(&TypeValue::Integer(Some(64))),
            TypeValue::Integer(Some(0))
        );
    }

    #[test]
    fn value_shr() {
        assert_eq!(
            TypeValue::Unknown.shr(&TypeValue::Bool(Some(true))),
            TypeValue::Unknown
        );
        assert_eq!(
            TypeValue::Bool(Some(true)).shr(&TypeValue::Unknown),
            TypeValue::Unknown
        );

        assert_eq!(
            TypeValue::Integer(Some(1)).shr(&TypeValue::Integer(Some(1))),
            TypeValue::Integer(Some(0))
        );

        assert_eq!(
            TypeValue::Integer(Some(2)).shr(&TypeValue::Integer(Some(1))),
            TypeValue::Integer(Some(1))
        );
    }
}
