use bstr::BString;
use serde::{Deserialize, Serialize};
use std::cell::OnceCell;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::{mem, ptr};
use walrus::ir::InstrSeqType;
use walrus::ValType;
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};

use crate::modules::protos::yara::enum_value_options::Value as EnumValue;
use crate::symbols::{Symbol, SymbolLookup, SymbolTable};
use crate::wasm::WasmExport;

pub(crate) use array::*;
pub(crate) use func::*;
pub(crate) use map::*;
pub(crate) use structure::*;

mod array;
mod func;
mod map;
mod structure;

/// The type of YARA expression or identifier.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum Type {
    #[default]
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
        write!(f, "{self:?}")
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
            _ => panic!("can not create WASM primitive type for `{ty}`"),
        }
    }
}

impl From<Type> for InstrSeqType {
    fn from(ty: Type) -> InstrSeqType {
        InstrSeqType::from(ValType::from(ty))
    }
}

/// Contains information about a value.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum Value<T> {
    /// Constant value. The value is known at compile time, and it cannot
    /// change at runtime.
    Const(T),
    /// Variable value. The value is known at compile time, but it can change
    /// at runtime.
    Var(T),
    /// The value is unknown at compile time.
    Unknown,
}

impl<T> Value<T> {
    /// Returns true if the value is constant.
    ///
    /// A constant value cannot change at runtime.
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
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
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
/// In the case of primitive types (integer, float, bool, and string), the
/// value can be constant, variable, or unknown. Structs, arrays, and maps
/// always have a reference to a [`Struct`], [`Array`] or [`Map`] respectively.
/// However, those structures, arrays, and maps don't contain actual values at
/// compile time, they only provide details about the type, like, for example,
/// which are the fields in a struct, or what's the type of the items in an
/// array.
///
/// Some types can have an optional set of constraints that give additional
/// information about the value. For instance, strings can have a constraint
/// [`StringConstraint::Lowercase`], which indicates that the string is always
/// lowercase.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum TypeValue {
    Unknown,
    Bool {
        value: Value<bool>,
    },
    Float {
        value: Value<f64>,
    },
    Integer {
        value: Value<i64>,
        constraints: Option<Vec<IntegerConstraint>>,
    },
    String {
        value: Value<Rc<BString>>,
        constraints: Option<Vec<StringConstraint>>,
    },
    Regexp(Option<Regexp>),
    Struct(Rc<Struct>),
    Array(Rc<Array>),
    Map(Rc<Map>),
    Func(Rc<Func>),
}

/// Each of the constraints allowed for string types.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum StringConstraint {
    /// The string is guaranteed to be lowercase.
    Lowercase,
    /// The string has an exact number of bytes.
    ExactLength(usize),
}

/// Each of the constraints allowed for integer types.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum IntegerConstraint {
    /// The integer is guaranteed to be within the given range.
    Range(i64, i64),
}

impl Hash for TypeValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);
        match self {
            TypeValue::Unknown => {}
            TypeValue::Integer { value, .. } => {
                mem::discriminant(value).hash(state);
                if let Value::Const(c) = value {
                    c.hash(state);
                }
            }
            TypeValue::Float { value } => {
                mem::discriminant(value).hash(state);
                if let Value::Const(c) = value {
                    // f64 doesn't implement the Hash trait. We hash the binary
                    // representation of the f64.
                    f64::to_bits(*c).hash(state);
                }
            }
            TypeValue::Bool { value } => {
                mem::discriminant(value).hash(state);
                if let Value::Const(c) = value {
                    c.hash(state);
                }
            }
            TypeValue::String { value, .. } => {
                mem::discriminant(value).hash(state);
                if let Value::Const(c) = value {
                    c.hash(state);
                }
            }
            TypeValue::Regexp(v) => {
                v.hash(state);
            }
            // In these cases we compute the hash of the reference itself,
            // not the hash of the referenced objects. This speeds-up the
            // hash computation because we don't need to traverse the
            // objects.
            TypeValue::Struct(v) => ptr::hash(&**v, state),
            TypeValue::Array(v) => ptr::hash(&**v, state),
            TypeValue::Map(v) => ptr::hash(&**v, state),
            TypeValue::Func(v) => ptr::hash(&**v, state),
        }
    }
}

impl TypeValue {
    /// Returns true if the [`TypeValue`] is a constant value.
    ///
    /// A constant value is one that is known at compile time and can't be
    /// changed at runtime.
    pub fn is_const(&self) -> bool {
        match self {
            TypeValue::Unknown => false,
            TypeValue::Integer { value, .. } => value.is_const(),
            TypeValue::Float { value } => value.is_const(),
            TypeValue::Bool { value } => value.is_const(),
            TypeValue::String { value, .. } => value.is_const(),
            TypeValue::Regexp(_) => false,
            TypeValue::Struct(_) => false,
            TypeValue::Array(_) => false,
            TypeValue::Map(_) => false,
            TypeValue::Func(_) => false,
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
            (Self::Integer { .. }, Self::Integer { .. }) => true,
            (Self::Float { .. }, Self::Float { .. }) => true,
            (Self::String { .. }, Self::String { .. }) => true,
            (Self::Bool { .. }, Self::Bool { .. }) => true,
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

    #[allow(clippy::declare_interior_mutable_const)]
    const STRING_BUILTIN_METHODS: OnceCell<Rc<SymbolTable>> = OnceCell::new();

    fn string_builtin_methods() -> Rc<SymbolTable> {
        #[allow(clippy::borrow_interior_mutable_const)]
        Self::STRING_BUILTIN_METHODS
            .get_or_init(|| {
                let mut s = SymbolTable::new();
                for (name, func) in WasmExport::get_methods("RuntimeString") {
                    s.insert(name, Symbol::Func(Rc::new(func)));
                }
                Rc::new(s)
            })
            .clone()
    }

    /// Returns the symbol table associated to this [`TypeValue`].
    ///
    /// The symbol table contains the methods and/or fields associated to the
    /// type.
    pub fn symbol_table(&self) -> Option<Rc<dyn SymbolLookup>> {
        match self {
            Self::Struct(s) => Some(s.clone()),
            Self::Array(_) => Some(Array::builtin_methods()),
            Self::Map(_) => Some(Map::builtin_methods()),
            Self::String { .. } => Some(Self::string_builtin_methods()),
            _ => None,
        }
    }

    /// Returns the type associated to the [`TypeValue`].
    pub fn ty(&self) -> Type {
        match self {
            Self::Unknown => Type::Unknown,
            Self::Integer { .. } => Type::Integer,
            Self::Float { .. } => Type::Float,
            Self::Bool { .. } => Type::Bool,
            Self::String { .. } => Type::String,
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
            Self::Integer { .. } => Self::unknown_integer(),
            Self::Float { .. } => Self::unknown_float(),
            Self::Bool { .. } => Self::unknown_bool(),
            Self::String { .. } => Self::unknown_string(),
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
            Self::Integer { value: Value::Unknown, .. } => {
                Self::Bool { value: Value::Unknown }
            }
            Self::Integer { value: Value::Var(i), .. } => {
                Self::Bool { value: Value::Var(*i != 0) }
            }
            Self::Integer { value: Value::Const(i), .. } => {
                Self::Bool { value: Value::Const(*i != 0) }
            }

            Self::Float { value: Value::Unknown } => {
                Self::Bool { value: Value::Unknown }
            }
            Self::Float { value: Value::Var(f) } => {
                Self::Bool { value: Value::Var(*f != 0.0) }
            }
            Self::Float { value: Value::Const(f) } => {
                Self::Bool { value: Value::Const(*f != 0.0) }
            }

            Self::String { value: Value::Unknown, .. } => {
                Self::Bool { value: Value::Unknown }
            }
            Self::String { value: Value::Var(s), .. } => {
                Self::Bool { value: Value::Var(!s.is_empty()) }
            }
            Self::String { value: Value::Const(s), .. } => {
                Self::Bool { value: Value::Const(!s.is_empty()) }
            }

            Self::Bool { value: Value::Unknown } => {
                Self::Bool { value: Value::Unknown }
            }
            Self::Bool { value: Value::Var(b) } => {
                Self::Bool { value: Value::Var(*b) }
            }
            Self::Bool { value: Value::Const(b) } => {
                Self::Bool { value: Value::Const(*b) }
            }

            _ => panic!("can not cast {self:?} to bool"),
        }
    }

    pub fn as_array(&self) -> Rc<Array> {
        if let TypeValue::Array(array) = self {
            array.clone()
        } else {
            panic!(
                "called `as_array` on a TypeValue that is not TypeValue::Array, it is: {self:?}"
            )
        }
    }

    pub fn as_struct(&self) -> Rc<Struct> {
        if let TypeValue::Struct(structure) = self {
            structure.clone()
        } else {
            panic!(
                "called `as_struct` on a TypeValue that is not TypeValue::Struct, it is: {self:?}"
            )
        }
    }

    pub fn as_map(&self) -> Rc<Map> {
        if let TypeValue::Map(map) = self {
            map.clone()
        } else {
            panic!(
                "called `as_map` on a TypeValue that is not TypeValue::Map, it is: {self:?}"
            )
        }
    }

    #[inline]
    pub fn as_bool(&self) -> bool {
        self.try_as_bool().expect("TypeValue doesn't have an associated value")
    }

    #[inline]
    pub fn as_integer(&self) -> i64 {
        self.try_as_integer()
            .expect("TypeValue doesn't have an associated value")
    }

    #[inline]
    pub fn as_float(&self) -> f64 {
        self.try_as_float()
            .expect("TypeValue doesn't have an associated value")
    }

    #[inline]
    pub fn as_string(&self) -> Rc<BString> {
        self.try_as_string()
            .expect("TypeValue doesn't have an associated value")
    }

    pub fn try_as_bool(&self) -> Option<bool> {
        if let TypeValue::Bool { value } = self {
            value.extract().cloned()
        } else {
            panic!(
                "called `try_as_bool` on a TypeValue that is not TypeValue::Bool, it is: {self:?}"
            )
        }
    }

    pub fn try_as_integer(&self) -> Option<i64> {
        if let TypeValue::Integer { value, .. } = self {
            value.extract().cloned()
        } else {
            panic!(
                "called `try_as_integer` on a TypeValue that is not TypeValue::Integer, it is: {self:?}"
            )
        }
    }

    pub fn try_as_float(&self) -> Option<f64> {
        if let TypeValue::Float { value } = self {
            value.extract().cloned()
        } else {
            panic!(
                "called `try_as_float` on a TypeValue that is not TypeValue::Float, it is: {self:?}"
            )
        }
    }

    pub fn try_as_string(&self) -> Option<Rc<BString>> {
        if let TypeValue::String { value, .. } = self {
            value.extract().cloned()
        } else {
            panic!(
                "called `try_as_string` on a TypeValue that is not TypeValue::String, it is: {self:?}"
            )
        }
    }

    /// Creates a new [`TypeValue`] consisting of a variable integer.
    #[inline]
    pub fn var_integer_from<T: Into<i64>>(i: T) -> Self {
        Self::Integer { value: Value::Var(i.into()), constraints: None }
    }

    /// Creates a new [`TypeValue`] consisting of a variable float.
    #[inline]
    pub fn var_float_from<T: Into<f64>>(f: T) -> Self {
        Self::Float { value: Value::Var(f.into()) }
    }

    /// Creates a new [`TypeValue`] consisting of a variable boolean.
    #[inline]
    pub fn var_bool_from(i: bool) -> Self {
        Self::Bool { value: Value::Var(i) }
    }

    /// Creates a new [`TypeValue`] consisting of a variable string.
    #[inline]
    pub fn var_string_from<T: AsRef<[u8]>>(s: T) -> Self {
        Self::String {
            value: Value::Var(BString::from(s.as_ref()).into()),
            constraints: None,
        }
    }

    /// Creates a new [`TypeValue`] consisting of a constant integer.
    #[inline]
    pub fn const_integer_from<T: Into<i64>>(i: T) -> Self {
        Self::Integer { value: Value::Const(i.into()), constraints: None }
    }

    /// Creates a new [`TypeValue`] consisting of a constant float.
    #[inline]
    pub fn const_float_from<T: Into<f64>>(f: T) -> Self {
        Self::Float { value: Value::Const(f.into()) }
    }

    /// Creates a new [`TypeValue`] consisting of a constant boolean.
    #[inline]
    pub fn const_bool_from(i: bool) -> Self {
        Self::Bool { value: Value::Const(i) }
    }

    /// Creates a new [`TypeValue`] consisting of a constant string.
    #[inline]
    pub fn const_string_from<T: AsRef<[u8]>>(s: T) -> Self {
        Self::String {
            value: Value::Const(BString::from(s.as_ref()).into()),
            constraints: None,
        }
    }

    /// Creates a new [`TypeValue`] consisting of an unknown string.
    #[inline]
    pub fn unknown_bool() -> Self {
        Self::Bool { value: Value::Unknown }
    }

    /// Creates a new [`TypeValue`] consisting of an unknown integer.
    #[inline]
    pub fn unknown_float() -> Self {
        Self::Float { value: Value::Unknown }
    }

    /// Creates a new [`TypeValue`] consisting of an unknown integer.
    #[inline]
    pub fn unknown_integer() -> Self {
        Self::Integer { value: Value::Unknown, constraints: None }
    }

    /// Creates a new [`TypeValue`] consisting of an unknown string.
    #[inline]
    pub fn unknown_string() -> Self {
        Self::String { value: Value::Unknown, constraints: None }
    }

    /// Creates a new [`TypeValue`] consisting of an unknown string with
    /// the given constraints.
    #[inline]
    pub fn unknown_string_with_constraints<C: Into<Vec<StringConstraint>>>(
        constraints: C,
    ) -> Self {
        Self::String {
            value: Value::Unknown,
            constraints: Some(constraints.into()),
        }
    }

    /// Creates a new [`TypeValue`] consisting of an unknown integer with
    /// the given constraints.
    #[inline]
    pub fn unknown_integer_with_constraints<
        C: Into<Vec<IntegerConstraint>>,
    >(
        constraints: C,
    ) -> Self {
        Self::Integer {
            value: Value::Unknown,
            constraints: Some(constraints.into()),
        }
    }

    pub fn value_as_json(&self) -> JsonValue {
        match self {
            Self::Unknown => JsonValue::Null,
            Self::Bool { value } => value.extract().cloned().map(JsonValue::Bool).unwrap_or(JsonValue::Null),
            Self::Integer { value, .. } => {
                if let Some(i) = value.extract().cloned() {
                    JsonValue::Number(JsonNumber::from(i))
                } else {
                    JsonValue::Null
                }
            }
            Self::Float {value} => {
                if let Some(f) = value.extract().cloned() {
                    JsonNumber::from_f64(f).map(JsonValue::Number).unwrap_or(JsonValue::Null)
                } else {
                    JsonValue::Null
                }
            }
            Self::String {value, ..} => {
                if let Some(s) = value.extract().cloned() {
                    let s_str = String::from_utf8_lossy(s.as_slice()).into_owned();
                    JsonValue::String(s_str)
                } else {
                    JsonValue::Null
                }
            }
            Self::Regexp(r) => {
                if let Some(re) = r {
                    JsonValue::String(re.as_str().to_string())
                } else {
                    JsonValue::Null
                }
            }
            Self::Struct(s) => {
                let mut obj = JsonMap::new();
                for (key, field) in s.fields().iter() {
                    obj.insert(key.clone(), field.type_value.value_as_json());
                }
                JsonValue::Object(obj)
            }
            Self::Array(a) => match a.as_ref() {
                Array::Integers(items) => JsonValue::Array(items.iter().map(|i| JsonValue::Number(JsonNumber::from(*i))).collect()),
                Array::Floats(items) => JsonValue::Array(items.iter().map(|f| JsonNumber::from_f64(*f).map(JsonValue::Number).unwrap_or(JsonValue::Null)).collect()),
                Array::Bools(items) => JsonValue::Array(items.iter().map(|b| JsonValue::Bool(*b)).collect()),
                Array::Strings(items) => JsonValue::Array(items.iter().map(|s| JsonValue::String(String::from_utf8_lossy(s.as_slice()).into_owned())).collect()),
                Array::Structs(items) => JsonValue::Array(items.iter().map(|st| {
                    let mut obj = JsonMap::new();
                    for (key, field) in st.fields().iter() {
                        obj.insert(key.clone(), field.type_value.value_as_json());
                    }
                    JsonValue::Object(obj)
                }).collect()),
            }
            Self::Map(m) => match m.as_ref() {
                Map::IntegerKeys { map, .. } => {
                    let mut obj = JsonMap::new();
                    for (k, v) in map.iter() {
                        obj.insert(k.to_string(), v.value_as_json());
                    }
                    JsonValue::Object(obj)
                }
                Map::StringKeys { map, .. } => {
                    let mut obj = JsonMap::new();
                    for (k, v) in map.iter() {
                        obj.insert(String::from_utf8_lossy(k.as_slice()).into_owned(), v.value_as_json());
                    }
                    JsonValue::Object(obj)
                }
            }
            Self::Func(_) => JsonValue::Null,
        }
    }
}

impl Display for TypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Debug for TypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Bool { value } => {
                if let Some(v) = value.extract() {
                    write!(f, "boolean({v:?})")
                } else {
                    write!(f, "boolean(unknown)")
                }
            }
            Self::Integer { value, .. } => {
                if let Some(v) = value.extract() {
                    write!(f, "integer({v:?})")
                } else {
                    write!(f, "integer(unknown)")
                }
            }
            Self::Float { value } => {
                if let Some(v) = value.extract() {
                    write!(f, "float({v:?})")
                } else {
                    write!(f, "float(unknown)")
                }
            }
            Self::String { value, .. } => {
                if let Some(v) = value.extract() {
                    write!(f, "string({v:?})")
                } else {
                    write!(f, "string(unknown)")
                }
            }
            Self::Regexp(re) => {
                if let Some(re) = re {
                    write!(f, "regexp({re:?})")
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

impl From<EnumValue> for TypeValue {
    fn from(value: EnumValue) -> Self {
        match value {
            EnumValue::I64(v) => Self::const_integer_from(v),
            EnumValue::F64(v) => Self::const_float_from(v),
        }
    }
}

impl PartialEq for TypeValue {
    fn eq(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (Self::Unknown, Self::Unknown) => true,
            (
                Self::String { value: lhs, .. },
                Self::String { value: rhs, .. },
            ) => lhs == rhs,
            (
                Self::Integer { value: lhs, .. },
                Self::Integer { value: rhs, .. },
            ) => lhs == rhs,
            (Self::Float { value: lhs }, Self::Float { value: rhs }) => {
                lhs == rhs
            }
            (Self::Bool { value: lhs }, Self::Bool { value: rhs }) => {
                lhs == rhs
            }
            (Self::Regexp(lhs), Self::Regexp(rhs)) => lhs == rhs,
            (Self::Struct(lhs), Self::Struct(rhs)) => ptr::eq(&**lhs, &**rhs),
            (Self::Array(lhs), Self::Array(rhs)) => ptr::eq(&**lhs, &**rhs),
            (Self::Map(lhs), Self::Map(rhs)) => ptr::eq(&**lhs, &**rhs),
            (Self::Func(lhs), Self::Func(rhs)) => ptr::eq(&**lhs, &**rhs),
            _ => false,
        }
    }
}

impl Eq for TypeValue {}
