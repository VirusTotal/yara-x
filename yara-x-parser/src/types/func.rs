use itertools::Itertools;

use crate::types::TypeValue;

#[derive(Clone, Debug)]
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

        let result = match ret {
            "i" => TypeValue::Integer(None),
            "f" => TypeValue::Float(None),
            "b" => TypeValue::Bool(None),
            "s" => TypeValue::String(None),
            _ => panic!("unexpected return type: `{}`", ret),
        };

        (args, result)
    }
}

impl From<String> for MangledFnName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

pub struct Func {
    mangled_name: MangledFnName,
    args: Vec<TypeValue>,
    result: TypeValue,
}

impl Func {
    /// Creates a [`Func`] struct from a [`MangledFnName`].
    ///
    /// The mangled name contains information about function arguments and
    /// return types, so it's possible to create a [`Func`] from it. See
    /// the documentation of [`MangledFnName`] for details.
    ///
    /// # Panics
    ///
    /// If the mangled doesn't have the correct structure.
    pub fn from_mangled_name(mangled_name: MangledFnName) -> Self {
        let (args, result) = mangled_name.unmangle();
        Self { mangled_name, args, result }
    }

    // Returns the function's arguments.
    #[inline]
    pub fn args(&self) -> &[TypeValue] {
        self.args.as_slice()
    }

    #[inline]
    pub fn result(&self) -> &TypeValue {
        &self.result
    }

    #[inline]
    pub fn mangled_name(&self) -> MangledFnName {
        self.mangled_name.clone()
    }
}
