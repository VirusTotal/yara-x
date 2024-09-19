use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::types::{TypeValue, Value};

#[derive(Clone, Debug, Eq, PartialEq)]
/// Represents a mangled function name.
///
/// A mangled name is a function name decorated with additional information
/// about the function's arguments and return types.
///
/// Mangled names have the format `<func name>@<arguments>@<return type>`,
/// where `<arguments>` is a sequence of characters, one per argument,
/// that specify the argument's type. Allowed types are:
///
/// ```text
///  i: integer
///  f: float
///  b: bool
///  s: string
///  r: regexp
/// ```
///
/// `<return type>` is also a sequence of one or more of the characters
/// above, specifying the types returned by the function (except `r`,
/// because functions can't return regular expressions). For example, a
/// function `add` with two integer arguments that return another integer
/// would have the mangled name `add@ii@i`. A function `foo` that returns
/// a tuple of two integers have the mangled name `foo@@ii`.
///
/// Additionally, the return type may be followed by a `u` character if
/// the returned value may be undefined. For example, a function `foo` that
/// receives no argument and returns a string that may be undefined will have
/// a mangled name: `foo@@su`.
///
/// Both `<arguments>` and `<return type>` can be empty if the function
/// doesn't receive arguments or doesn't return a value. Let's see some e
/// examples:
///
/// ```text
/// foo()                          ->  foo@@
/// foo(i: i64)                    ->  foo@i@
/// foo() -> i32                   ->  foo@@i
/// foo() -> Option<()>            ->  foo@@u
/// foo() -> Option<f32>           ->  foo@@fu
/// foo() -> Option<(f64,f64)>     ->  foo@@ffu
/// ```
#[derive(Serialize, Deserialize)]
pub(crate) struct MangledFnName(String);

impl MangledFnName {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl MangledFnName {
    /// Returns the types of arguments and return value for the function.
    pub fn unmangle(&self) -> (Vec<TypeValue>, TypeValue) {
        let (_name, arg_types, ret) =
            self.0.split('@').collect_tuple().unwrap_or_else(|| {
                panic!("invalid mangled name: `{}`", self.0)
            });

        let mut args = vec![];

        for t in arg_types.chars() {
            match t {
                'i' => args.push(TypeValue::Integer(Value::Unknown)),
                'f' => args.push(TypeValue::Float(Value::Unknown)),
                'b' => args.push(TypeValue::Bool(Value::Unknown)),
                's' => args.push(TypeValue::String(Value::Unknown)),
                'r' => args.push(TypeValue::Regexp(None)),
                _ => panic!("unexpected argument type: `{}`", t),
            }
        }

        let result = if let Some(ret) = ret.get(0..1) {
            match ret.get(0..1).unwrap() {
                "i" => TypeValue::Integer(Value::Unknown),
                "f" => TypeValue::Float(Value::Unknown),
                "b" => TypeValue::Bool(Value::Unknown),
                "s" => TypeValue::String(Value::Unknown),
                "u" => TypeValue::Unknown,
                _ => panic!("unexpected return type: `{}`", ret),
            }
        } else {
            TypeValue::Unknown
        };

        (args, result)
    }

    /// Returns true if the function's result may be undefined.
    #[inline]
    pub fn result_may_be_undef(&self) -> bool {
        self.0.ends_with('u')
    }
}

impl<S> From<S> for MangledFnName
where
    S: Into<String>,
{
    fn from(value: S) -> Self {
        Self(value.into())
    }
}

/// Represents a function's signature.
///
/// YARA modules allow function overloading, therefore functions can have the
/// same name but different arguments.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct FuncSignature {
    pub mangled_name: MangledFnName,
    pub args: Vec<TypeValue>,
    pub result: TypeValue,
    pub result_may_be_undef: bool,
}

impl Ord for FuncSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.mangled_name.as_str().cmp(other.mangled_name.as_str())
    }
}

impl PartialOrd for FuncSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.mangled_name.as_str().cmp(other.mangled_name.as_str()))
    }
}

impl Eq for FuncSignature {}

impl PartialEq for FuncSignature {
    fn eq(&self, other: &Self) -> bool {
        self.mangled_name == other.mangled_name
    }
}

impl<T: Into<String>> From<T> for FuncSignature {
    fn from(value: T) -> Self {
        let mangled_name = MangledFnName::from(value.into());
        let result_may_be_undef = mangled_name.result_may_be_undef();
        let (args, result) = mangled_name.unmangle();
        Self { mangled_name, args, result, result_may_be_undef }
    }
}

/// A type representing a function.
///
/// Represents both functions and methods. As in any programming language
/// methods are functions associated to a type that receive an instance
/// of that type as their first argument.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Func {
    /// The list of signatures for this function. Functions can be overloaded,
    /// so they may more than one signature.
    signatures: Vec<FuncSignature>,
    /// If this function is a method, contains the name of the type the method
    /// is associated to. For standard functions this is [`None`].
    method_of: Option<String>,
}

impl Func {
    /// Creates a new [`Func`] from a mangled function name.
    pub fn from_mangled_name(name: &str) -> Self {
        Self { signatures: vec![FuncSignature::from(name)], method_of: None }
    }

    /// Makes this function a method of the specified type.
    pub fn make_method_of(&mut self, type_name: &str) {
        self.method_of = Some(type_name.to_string())
    }

    /// If this function is a method of some type, returns the name of the
    /// type. Returns [`None`] if the function is not a method.
    pub fn method_of(&self) -> Option<&str> {
        self.method_of.as_deref()
    }

    /// Add a signature to the function.
    ///
    /// # Panics
    ///
    /// If the function already has the given signature.
    pub fn add_signature(&mut self, signature: FuncSignature) {
        // Signatures are inserted into self.signatures sorted by
        // mangled named.
        match self.signatures.binary_search(&signature) {
            Ok(_) => {
                panic!(
                    "function `{}` is implemented twice",
                    signature.mangled_name.as_str()
                )
            }
            Err(pos) => self.signatures.insert(pos, signature),
        }
    }

    /// Returns all the signatures for this function.
    #[inline]
    pub fn signatures(&self) -> &[FuncSignature] {
        self.signatures.as_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::types::{MangledFnName, TypeValue, Value};
    use pretty_assertions::assert_eq;

    #[test]
    fn mangled_name() {
        assert_eq!(
            MangledFnName::from("foo@@i").unmangle(),
            (vec![], TypeValue::Integer(Value::Unknown))
        );

        assert_eq!(
            MangledFnName::from("foo@i@i").unmangle(),
            (
                vec![TypeValue::Integer(Value::Unknown)],
                TypeValue::Integer(Value::Unknown)
            )
        );

        assert_eq!(
            MangledFnName::from("foo@f@f").unmangle(),
            (
                vec![TypeValue::Float(Value::Unknown)],
                TypeValue::Float(Value::Unknown)
            )
        );

        assert_eq!(
            MangledFnName::from("foo@b@b").unmangle(),
            (
                vec![TypeValue::Bool(Value::Unknown)],
                TypeValue::Bool(Value::Unknown)
            )
        );

        assert_eq!(
            MangledFnName::from("foo@s@s").unmangle(),
            (
                vec![TypeValue::String(Value::Unknown)],
                TypeValue::String(Value::Unknown)
            )
        );

        assert!(!MangledFnName::from("foo@i@i").result_may_be_undef());
        assert!(MangledFnName::from("foo@i@iu").result_may_be_undef());
    }

    #[test]
    #[should_panic]
    fn invalid_mangled_name_1() {
        MangledFnName::from("foo@i").unmangle();
    }

    #[test]
    #[should_panic]
    fn invalid_mangled_name_2() {
        MangledFnName::from("foo@@x").unmangle();
    }

    #[test]
    #[should_panic]
    fn invalid_mangled_name_3() {
        MangledFnName::from("foo@x@i").unmangle();
    }
}
