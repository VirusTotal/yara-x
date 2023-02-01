use itertools::Itertools;
use std::cmp::Ordering;

use crate::types::TypeValue;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Represents a mangled function name.
///
/// A mangled name is a function name decorated with additional information
/// about the function's arguments and return types.
///
/// Mangled names have the format `<func name>@<arguments>@<return type>`,
//  where `<arguments>` is a sequence of characters, one per argument,
//  that specify the argument's type. Allowed types are:
//
//  ```text
//   i: integer
//   f: float
//   b: bool
//   s: string
//   r: regexp
//  ```
//
//  `<return type>` is also one of the characters above, specifying the
//  type of the returned by the function (except `r`, because functions
//  can't return regular expressions). For example, a function `add` with
//  two integer arguments that return another integer would have the
//  mangled name: `add@ii@i`.
//
//  Additionally, the return type may be followed by a `u` character if
//  the returned value may be undefined. For example, a function `foo` that
//  receives no argument and returns a string that may undefined will have
//  a mangled name: `foo@@su`.
//
pub struct MangledFnName(String);

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
                'i' => args.push(TypeValue::Integer(None)),
                'f' => args.push(TypeValue::Float(None)),
                'b' => args.push(TypeValue::Bool(None)),
                's' => args.push(TypeValue::String(None)),
                'r' => args.push(TypeValue::Regexp(None)),
                _ => panic!("unexpected argument type: `{}`", t),
            }
        }

        let result = match ret.get(0..1).unwrap() {
            "i" => TypeValue::Integer(None),
            "f" => TypeValue::Float(None),
            "b" => TypeValue::Bool(None),
            "s" => TypeValue::String(None),
            _ => panic!("unexpected return type: `{}`", ret),
        };

        (args, result)
    }

    // Returns true if the function's result may be undefined.
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
#[derive(Clone)]
pub struct FuncSignature {
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

impl From<String> for FuncSignature {
    fn from(value: String) -> Self {
        let mangled_name = MangledFnName::from(value);
        let result_may_be_undef = mangled_name.result_may_be_undef();
        let (args, result) = mangled_name.unmangle();
        Self { mangled_name, args, result, result_may_be_undef }
    }
}

#[derive(Clone)]
pub struct Func {
    signatures: Vec<FuncSignature>,
}

impl Func {
    pub fn with_signature(signature: FuncSignature) -> Self {
        Self { signatures: vec![signature] }
    }

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

    pub fn signatures(&self) -> &[FuncSignature] {
        self.signatures.as_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::types::{MangledFnName, TypeValue};
    use pretty_assertions::assert_eq;

    #[test]
    fn mangled_name() {
        assert_eq!(
            MangledFnName::from("foo@@i").unmangle(),
            (vec![], TypeValue::Integer(None))
        );

        assert_eq!(
            MangledFnName::from("foo@i@i").unmangle(),
            (vec![TypeValue::Integer(None)], TypeValue::Integer(None))
        );

        assert_eq!(
            MangledFnName::from("foo@f@f").unmangle(),
            (vec![TypeValue::Float(None)], TypeValue::Float(None))
        );

        assert_eq!(
            MangledFnName::from("foo@b@b").unmangle(),
            (vec![TypeValue::Bool(None)], TypeValue::Bool(None))
        );

        assert_eq!(
            MangledFnName::from("foo@s@s").unmangle(),
            (vec![TypeValue::String(None)], TypeValue::String(None))
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
