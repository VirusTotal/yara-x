use crate::types::{IntegerConstraint, StringConstraint, TypeValue};
use itertools::Itertools;
use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::iter::Peekable;
use std::rc::Rc;
use std::str::Chars;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Represents a mangled function name.
///
/// A mangled name is a function name decorated with additional information
/// about the function's arguments and return types.
///
/// Mangled names have the format:
///   
/// `[<type name>::]<func name>@<arguments>@<return type>`
///
/// The prefix `<type name>::` is optional, it is present only if the function
/// is a method of the type identified by `<type name>`. `<arguments>` is a
/// comma-separated list of `<name>:<type>` pairs, where `<name>` is the name
/// of the argument, and `<type>` is a sequence of characters that specify the
/// argument's type. Allowed type characters are:
///
/// ```text
///  i: integer
///  f: float
///  b: bool
///  s: string
///  r: regexp
/// ```
///
/// `<return type>` is a sequence of one or more of the characters above,
/// specifying the type returned by the function (except `r`, because
/// functions can't return regular expressions). For example, a function `add`
/// with two integer arguments `a` and `b` that returns another integer
/// would have the mangled name `add@a:i,b:i@i`. A function `foo` that takes no
/// arguments and returns a tuple of two integers has the mangled name `foo@@ii`.
///
/// Additionally, the return type may be followed by a `u` character if
/// the returned value may be undefined. For example, a function `foo` that
/// receives no argument and returns a string that may be undefined will have
/// a mangled name: `foo@@su`.
///
/// Both `<arguments>` and `<return type>` can be empty if the function
/// doesn't receive arguments or doesn't return a value. Let's see some
/// examples:
///
/// ```text
/// foo()                          ->  foo@@
/// foo(a: i64)                    ->  foo@a:i@
/// foo() -> i32                   ->  foo@@i
/// foo() -> Option<()>            ->  foo@@u
/// foo() -> Option<f32>           ->  foo@@fu
/// foo() -> Option<(f64,f64)>     ->  foo@@ffu
/// ```
///
/// ### Type Constraints
///
/// Types may include constraints that specify additional restrictions on
/// their values. A constraint follows the type character, separated by a
/// colon, and consists of an uppercase letter (representing the constraint
/// type) and possibly additional characters, depending on the constraint.
///
/// Examples:
///
/// ```text
/// foo() -> lowercase string           _> foo@@s:L
/// foo() -> uppercase string           _> foo@@s:U
/// foo() -> string of length 32        _> foo@@s:N32
/// foo() -> 32-byte lowercase string   -> foo@@s:N32:L
/// foo() -> 32-byte uppercase string   -> foo@@s:N32:U
/// foo() -> integer in the range 0-255 -> foo@@i:R0:255
/// ```
///
/// Multiple constraints can be chained by appending them in sequence after
/// the type character.
#[derive(Serialize, Deserialize, Hash)]
pub(crate) struct MangledFnName(String);

impl MangledFnName {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl MangledFnName {
    /// Returns the types of arguments and return value for the function.
    pub fn unmangle(&self) -> (Vec<(&str, TypeValue)>, TypeValue) {
        let (_fn_name, arg_names_and_types, ret_type) =
            self.0.split('@').collect_tuple().unwrap_or_else(|| {
                panic!("invalid mangled name: `{}`", self.0)
            });

        let mut args = Vec::new();

        if !arg_names_and_types.is_empty() {
            for arg_str in arg_names_and_types.split(',') {
                let (arg_name, arg_type) =
                    if let Some((n, t)) = arg_str.split_once(':') {
                        (n, t)
                    } else {
                        panic!(
                            "argument name missing in mangled name: `{}`",
                            self.0
                        )
                    };

                let mut chars = arg_type.chars().peekable();
                let type_value =
                    self.next_type(&mut chars).unwrap_or_else(|| {
                        panic!(
                            "invalid argument type in mangled name: `{}`",
                            self.0
                        )
                    });
                args.push((arg_name, type_value));
            }
        }

        let mut chars = ret_type.chars().peekable();
        let ret = self.next_type(&mut chars).unwrap_or_else(|| {
            panic!("expecting return type in mangled name: `{}`", self.0)
        });

        // Return type can't be a regexp.
        assert!(!matches!(ret, TypeValue::Regexp(_)));

        (args, ret)
    }

    /// Returns true if the function's result may be undefined.
    #[inline]
    pub fn result_may_be_undef(&self) -> bool {
        self.0.ends_with('u')
    }

    /// If this function is a method of some type, returns the type name.
    pub fn method_of(&self) -> Option<&str> {
        self.0.split_once("::").map(|(type_name, _)| type_name)
    }

    fn next_type(&self, chars: &mut Peekable<Chars>) -> Option<TypeValue> {
        match chars.next() {
            Some('u') => Some(TypeValue::Unknown),
            Some('r') => Some(TypeValue::Regexp(None)),
            Some('f') => Some(TypeValue::unknown_float()),
            Some('b') => Some(TypeValue::unknown_bool()),
            Some('i') => {
                let mut constraints = Vec::new();

                while let Some(':') = chars.peek() {
                    chars.next(); // consume the colon (:)
                    match chars.next() {
                        Some('R') => {
                            let min = self.parse_i64(chars);
                            assert_eq!(chars.next(), Some(':'));
                            let max = self.parse_i64(chars);
                            constraints
                                .push(IntegerConstraint::Range(min, max));
                        }
                        None | Some(_) => {
                            panic!("invalid mangled name: `{}`", self.0)
                        }
                    }
                }

                Some(if constraints.is_empty() {
                    TypeValue::unknown_integer()
                } else {
                    TypeValue::unknown_integer_with_constraints(constraints)
                })
            }
            Some('s') => {
                let mut constraints = Vec::new();

                while let Some(':') = chars.peek() {
                    chars.next(); // consume the colon (:)
                    match chars.next() {
                        Some('L') => {
                            constraints.push(StringConstraint::Lowercase);
                        }
                        Some('U') => {
                            constraints.push(StringConstraint::Uppercase);
                        }
                        Some('N') => {
                            let n = self.parse_i64(chars);
                            constraints.push(StringConstraint::ExactLength(
                                n as usize,
                            ));
                        }
                        None | Some(_) => {
                            panic!("invalid mangled name: `{}`", self.0)
                        }
                    }
                }

                Some(if constraints.is_empty() {
                    TypeValue::unknown_string()
                } else {
                    TypeValue::unknown_string_with_constraints(constraints)
                })
            }
            Some(c) => {
                panic!("unknown type `{}` in mangled name: `{}`", c, self.0)
            }
            None => None,
        }
    }

    fn parse_i64(&self, chars: &mut Peekable<Chars>) -> i64 {
        chars
            .by_ref()
            .peeking_take_while(|&c| c.is_ascii_digit() || c == '-')
            .collect::<String>()
            .parse::<i64>()
            .unwrap_or_else(|_| panic!("invalid mangled name: `{}`", self.0))
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
/// YARA modules allow function overloading, therefore, functions can have the
/// same name but different arguments.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct FuncSignature {
    pub mangled_name: MangledFnName,
    pub args: Vec<(String, TypeValue)>,
    pub result: TypeValue,
    pub doc: Option<Cow<'static, str>>,
}

impl FuncSignature {
    /// Returns true if the function's result may be undefined.
    #[inline]
    pub fn result_may_be_undef(&self) -> bool {
        self.mangled_name.result_may_be_undef()
    }

    /// If this function is a method of some type, returns the type name.
    #[inline]
    pub fn method_of(&self) -> Option<&str> {
        self.mangled_name.method_of()
    }
}

impl Hash for FuncSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.mangled_name.hash(state);
    }
}

impl Ord for FuncSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.mangled_name.as_str().cmp(other.mangled_name.as_str())
    }
}

impl PartialOrd for FuncSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for FuncSignature {}

impl PartialEq for FuncSignature {
    fn eq(&self, other: &Self) -> bool {
        self.mangled_name == other.mangled_name
    }
}

impl<T: Into<String>> From<T> for FuncSignature {
    /// Creates a [`FuncSignature`] from a string containing a mangled function name.
    fn from(value: T) -> Self {
        let mangled_name = MangledFnName::from(value.into());
        let (args_with_names, result) = mangled_name.unmangle();

        let mut args = Vec::with_capacity(args_with_names.len());
        for (name, ty) in args_with_names {
            args.push((name.to_string(), ty));
        }

        Self { mangled_name, args, result, doc: None }
    }
}

/// A type representing a function.
///
/// Represents both functions and methods. As in any programming language
/// methods are functions associated to a type that receive an instance
/// of that type as their first argument.
#[derive(Clone, Serialize, Deserialize, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Func {
    /// The list of signatures for this function. Functions can be overloaded,
    /// so they may more than one signature.
    signatures: Vec<Rc<FuncSignature>>,
    /// If this function is a method, this field contains the name of the
    /// type. `None` indicates that this is a standard function, not a method.
    method_of: Option<String>,
}

impl<T: Into<String>> From<T> for Func {
    /// Creates a [`Func`] from a string containing a mangled function name.
    fn from(value: T) -> Self {
        let signature = FuncSignature::from(value);
        let method_of = signature.method_of().map(String::from);
        Self { signatures: vec![Rc::new(signature)], method_of }
    }
}

impl Func {
    /// Returns `true` if this function is a method.
    pub fn is_method(&self) -> bool {
        self.method_of.is_some()
    }

    /// Adds a signature to the function.
    ///
    /// If any of the added signatures is a method associated with a specific type,
    /// all other signatures must also be methods for the same type.
    ///
    /// # Panics
    ///
    /// Panics if the function already contains the given signature, or if the added
    /// signature is a method for a different type than the one used in existing
    /// method signatures.
    pub fn add_signature(&mut self, signature: FuncSignature) {
        if let Some(method_of) = &self.method_of {
            assert_eq!(signature.method_of(), Some(method_of.as_str()));
        }

        let signature = Rc::new(signature);
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
    pub fn signatures(&self) -> &[Rc<FuncSignature>] {
        self.signatures.as_slice()
    }

    /// Returns all the signatures for this function, but mutable.
    #[inline]
    pub fn signatures_mut(&mut self) -> &mut [Rc<FuncSignature>] {
        self.signatures.as_mut_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::types::{
        IntegerConstraint, MangledFnName, StringConstraint, TypeValue,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn mangled_name() {
        assert_eq!(
            MangledFnName::from("foo@@i").unmangle(),
            (vec![], TypeValue::unknown_integer())
        );

        assert_eq!(
            MangledFnName::from("foo@a:i,b:i@i").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_integer()),
                    ("b", TypeValue::unknown_integer())
                ],
                TypeValue::unknown_integer()
            )
        );

        assert_eq!(
            MangledFnName::from("foo@a:f,b:f@f").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_float()),
                    ("b", TypeValue::unknown_float())
                ],
                TypeValue::unknown_float()
            )
        );

        assert_eq!(
            MangledFnName::from("foo@a:b,b:b@b").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_bool()),
                    ("b", TypeValue::unknown_bool())
                ],
                TypeValue::unknown_bool()
            )
        );

        assert_eq!(
            MangledFnName::from("foo@a:s,b:s@s").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_string()),
                    ("b", TypeValue::unknown_string())
                ],
                TypeValue::unknown_string()
            )
        );

        assert_eq!(
            MangledFnName::from("foo@a:s,b:s:L@s:L").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_string()),
                    (
                        "b",
                        TypeValue::unknown_string_with_constraints(vec![
                            StringConstraint::Lowercase
                        ])
                    )
                ],
                TypeValue::unknown_string_with_constraints(vec![
                    StringConstraint::Lowercase
                ])
            )
        );

        assert_eq!(
            MangledFnName::from("foo@a:s,b:s:U@s:U").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_string()),
                    (
                        "b",
                        TypeValue::unknown_string_with_constraints(vec![
                            StringConstraint::Uppercase
                        ])
                    )
                ],
                TypeValue::unknown_string_with_constraints(vec![
                    StringConstraint::Uppercase
                ])
            )
        );

        assert_eq!(
            MangledFnName::from("foo@a:s,b:s:N16@s:N16").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_string()),
                    (
                        "b",
                        TypeValue::unknown_string_with_constraints(vec![
                            StringConstraint::ExactLength(16),
                        ])
                    )
                ],
                TypeValue::unknown_string_with_constraints(vec![
                    StringConstraint::ExactLength(16),
                ])
            )
        );

        assert_eq!(
            MangledFnName::from("foo@a:s,b:s:N16:L@s:N16:L").unmangle(),
            (
                vec![
                    ("a", TypeValue::unknown_string()),
                    (
                        "b",
                        TypeValue::unknown_string_with_constraints(vec![
                            StringConstraint::ExactLength(16),
                            StringConstraint::Lowercase
                        ])
                    )
                ],
                TypeValue::unknown_string_with_constraints(vec![
                    StringConstraint::ExactLength(16),
                    StringConstraint::Lowercase
                ])
            )
        );

        assert_eq!(
            MangledFnName::from("foo@@i:R0:10").unmangle(),
            (
                vec![],
                TypeValue::unknown_integer_with_constraints(vec![
                    IntegerConstraint::Range(0, 10),
                ])
            )
        );

        assert_eq!(
            MangledFnName::from("foo@@i:R-100:1000").unmangle(),
            (
                vec![],
                TypeValue::unknown_integer_with_constraints(vec![
                    IntegerConstraint::Range(-100, 1000),
                ])
            )
        );

        assert_eq!(
            MangledFnName::from("Bar::foo@a:i,b:i@iu").method_of(),
            Some("Bar")
        );

        assert_eq!(
            MangledFnName::from("bar.Bar::foo@a:i,b:i@iu").method_of(),
            Some("bar.Bar")
        );

        assert_eq!(MangledFnName::from("foo@a:i,b:i@iu").method_of(), None);

        assert!(!MangledFnName::from("foo@a:i,b:i@i").result_may_be_undef());
        assert!(MangledFnName::from("foo@a:i,b:i@iu").result_may_be_undef());
    }

    #[test]
    #[should_panic]
    fn invalid_mangled_name_1() {
        MangledFnName::from("foo@a:i").unmangle();
    }

    #[test]
    #[should_panic]
    fn invalid_mangled_name_2() {
        MangledFnName::from("foo@@x").unmangle();
    }

    #[test]
    #[should_panic]
    fn invalid_mangled_name_3() {
        MangledFnName::from("foo@a:x@i").unmangle();
    }

    #[test]
    #[should_panic]
    fn missing_argument_name() {
        MangledFnName::from("foo@i@i").unmangle();
    }
}
