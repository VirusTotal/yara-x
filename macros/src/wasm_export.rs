extern crate proc_macro;

use std::borrow::Cow;
use std::collections::vec_deque::VecDeque;
use std::ops::Add;

use darling::FromMeta;
use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::visit::Visit;
use syn::{
    AngleBracketedGenericArguments, Error, Expr, ExprLit, GenericArgument,
    Ident, ItemFn, Lit, PatType, PathArguments, Result, ReturnType, Type,
    TypePath,
};

/// Parses the signature of a Rust function and returns its mangled named.
struct FuncSignatureParser<'ast> {
    arg_types: Option<VecDeque<&'ast Type>>,
}

impl<'ast> FuncSignatureParser<'ast> {
    fn new() -> Self {
        Self { arg_types: None }
    }

    #[inline(always)]
    fn type_ident(type_path: &TypePath) -> &Ident {
        &type_path.path.segments.last().unwrap().ident
    }

    /// Returns an iterator with the generic arguments for the type specified
    /// by `type_path`.
    ///
    /// Returns an error if the type doesn't have generic arguments.
    #[inline(always)]
    fn type_args(
        type_path: &TypePath,
    ) -> Result<impl Iterator<Item = &GenericArgument>> {
        if let PathArguments::AngleBracketed(
            AngleBracketedGenericArguments { args, .. },
        ) = &type_path.path.segments.last().unwrap().arguments
        {
            Ok(args.into_iter())
        } else {
            Err(Error::new_spanned(type_path, "this type must have arguments"))
        }
    }

    /// Returns the generic arguments for the type specified by `type_path`,
    /// but only if all the generic arguments are integers.
    ///
    /// Returns an error if the type doesn't have generic arguments or if any
    /// of the arguments is not a literal integer.
    fn type_args_as_integers(
        type_path: &TypePath,
        error_msg: &str,
    ) -> Result<Vec<i64>> {
        Self::type_args(type_path)?
            .map(|arg| match arg {
                GenericArgument::Const(Expr::Lit(ExprLit {
                    lit: Lit::Int(integer),
                    ..
                })) => integer.base10_parse(),
                _ => Err(Error::new_spanned(type_path, error_msg)),
            })
            .collect::<Result<Vec<_>>>()
    }

    fn type_path_to_mangled_named(
        type_path: &TypePath,
    ) -> Result<Cow<'static, str>> {
        match Self::type_ident(type_path).to_string().as_str() {
            "i32" | "i64" => Ok(Cow::Borrowed("i")),
            "f32" | "f64" => Ok(Cow::Borrowed("f")),
            "bool" => Ok(Cow::Borrowed("b")),

            "PatternId" | "RuleId" => Ok(Cow::Borrowed("i")),
            "RegexpId" => Ok(Cow::Borrowed("r")),
            "Rc" => Ok(Cow::Borrowed("i")),
            "RuntimeObjectHandle" => Ok(Cow::Borrowed("i")),
            "RuntimeString" => Ok(Cow::Borrowed("s")),
            "RangedInteger" => {
                let error_msg = "RangedInteger must have MIN and MAX arguments (i.e: RangedInteger<0,256>)";
                let args = Self::type_args_as_integers(type_path, error_msg)?;

                let min = args
                    .first()
                    .ok_or_else(|| Error::new_spanned(type_path, error_msg))?;

                let max = args
                    .get(1)
                    .ok_or_else(|| Error::new_spanned(type_path, error_msg))?;

                Ok(Cow::Owned(format!("i:R{min:?}:{max:?}")))
            }
            "FixedLenString" => {
                let error_msg = "FixedLenString must have a constant length (i.e: FixedLenString<32>)";
                let args = Self::type_args_as_integers(type_path, error_msg)?;

                let n = args
                    .first()
                    .ok_or_else(|| Error::new_spanned(type_path, error_msg))?;

                Ok(Cow::Owned(format!("s:N{n:?}")))
            }
            "Lowercase" => {
                let mut args = Self::type_args(type_path)?;
                if let Some(GenericArgument::Type(Type::Path(p))) = args.next()
                {
                    Ok(Self::type_path_to_mangled_named(p)?.add(":L"))
                } else {
                    Err(Error::new_spanned(
                        type_path,
                        "Lowercase must have a type argument (i.e: <Lowercase<RuntimeString>>))",
                    ))
                }
            }
            type_ident => Err(Error::new_spanned(
                type_path,
                format!(
                    "type `{type_ident}` is not supported as argument or return type"
                ),
            )),
        }
    }

    fn mangled_type(ty: &Type) -> Result<Cow<'static, str>> {
        match ty {
            Type::Path(type_path) => {
                if Self::type_ident(type_path) == "Option" {
                    if let PathArguments::AngleBracketed(angle_bracketed) =
                        &type_path.path.segments.last().unwrap().arguments
                    {
                        if let GenericArgument::Type(ty) =
                            angle_bracketed.args.first().unwrap()
                        {
                            Ok(Self::mangled_type(ty)?.add("u"))
                        } else {
                            unreachable!()
                        }
                    } else {
                        unreachable!()
                    }
                } else {
                    Self::type_path_to_mangled_named(type_path)
                }
            }
            Type::Group(group) => Self::mangled_type(group.elem.as_ref()),
            Type::Tuple(tuple) => {
                let mut result = String::new();
                for elem in tuple.elems.iter() {
                    result.push_str(Self::mangled_type(elem)?.as_ref());
                }
                Ok(Cow::Owned(result))
            }
            _ => Err(Error::new_spanned(ty, "unsupported type")),
        }
    }

    fn mangled_return_type(ty: &ReturnType) -> Result<Cow<'static, str>> {
        match ty {
            // The function doesn't return anything.
            ReturnType::Default => Ok(Cow::Borrowed("")),
            // The function returns some type.
            ReturnType::Type(_, ty) => Self::mangled_type(ty),
        }
    }

    fn parse(&mut self, func: &'ast ItemFn) -> Result<String> {
        self.arg_types = Some(VecDeque::new());

        // This loop traverses the function arguments' AST, populating
        // `self.arg_types`.
        for fn_arg in func.sig.inputs.iter() {
            self.visit_fn_arg(fn_arg);
        }

        let mut arg_types = self.arg_types.take().unwrap();

        let mut first_argument_is_ok = false;

        // Make sure that the first argument is `&mut Caller`.
        if let Some(Type::Reference(ref_type)) = arg_types.pop_front() {
            if let Type::Path(type_) = ref_type.elem.as_ref() {
                first_argument_is_ok = Self::type_ident(type_) == "Caller";
            }
        }

        if !first_argument_is_ok {
            return Err(Error::new_spanned(
                &func.sig,
                format!(
                    "the first argument for function `{}` must be `&mut Caller<'_, ScanContext>`",
                    func.sig.ident),
            ));
        }

        let mut mangled_name = String::from("@");

        for arg_type in arg_types {
            mangled_name.push_str(Self::mangled_type(arg_type)?.as_ref());
        }

        mangled_name.push('@');
        mangled_name.push_str(&Self::mangled_return_type(&func.sig.output)?);

        Ok(mangled_name)
    }
}

impl<'ast> Visit<'ast> for FuncSignatureParser<'ast> {
    fn visit_pat_type(&mut self, pat_type: &'ast PatType) {
        self.arg_types.as_mut().unwrap().push_back(pat_type.ty.as_ref());
    }
}

#[derive(Debug, FromMeta)]
/// Arguments received by the `#[wasm_export]` macro.
pub struct WasmExportArgs {
    name: Option<String>,
    method_of: Option<String>,
    #[darling(default)]
    public: bool,
}

/// Implementation for the `#[wasm_export]` attribute macro.
///
/// This attribute is used in functions that will be called from WASM.
/// For each function using this attribute adds an entry in a global
/// registry that tracks all the functions that may be called from WASM.
///
/// Under the hood, this macro uses either the `linkme` or the `inventory`
/// crate for maintaining the global registry. In the first case, a
/// `WasmExport` is added to the global `WASM_EXPORTS` slice, while in
/// the second cases it uses the `inventory::submit!` for adding a
/// `WasmExport` struct to the inventory.
///
/// # Example
///
/// Suppose that our function is:
///
/// ```text
/// #[wasm_export]
/// fn add(caller: &mut Caller<'_, ScanContext>, a: i64, b: i64) -> i64 {
///     a + b
/// }
/// ```
///
/// The code generated will be:
///
/// ```text
/// #[cfg_attr(not(feature = "inventory"), distributed_slice(WASM_EXPORTS))]
/// pub(crate) static export__add: WasmExport = WasmExport {
///     name: "add",
///     mangled_name: "add@ii@i",
///     rust_module_path: "yara_x::modules::my_module",
///     method_of: None,
///     func: &WasmExportedFn2 { target_fn: &add },
/// };
///
/// #[cfg(feature = "inventory")]
/// inventory::submit! {
///     WasmExport {
///         name: #fn_name,
///         mangled_name: #mangled_fn_name,
///         public: #public,
///         rust_module_path: module_path!(),
///         method_of: #method_of,
///         func: &#exported_fn_ident { target_fn: &#rust_fn_name },
///     }
/// }
/// ```
///
/// Notice that the generated code uses `WasmExportedFn2` because the function
/// receives two parameters (not counting `caller: &mut Caller<'_, ScanContext>`)
///
pub(crate) fn impl_wasm_export_macro(
    attr_args: Vec<darling::ast::NestedMeta>,
    func: ItemFn,
) -> Result<TokenStream> {
    let attr_args = WasmExportArgs::from_list(attr_args.as_slice())?;
    let rust_fn_name = &func.sig.ident;

    if func.sig.inputs.is_empty() {
        return Err(Error::new_spanned(
            &func.sig,
            format!(
                "function `{rust_fn_name}` must have at least one argument of type `&mut Caller<'_, ScanContext>`"),
        ));
    }

    // By default, the name of the function in YARA is equal to the name in
    // Rust, but the YARA name can be changed with the `name` argument, as
    // in: #[wasm_export(name = "some_other_name")].
    let fn_name = attr_args.name.unwrap_or(rust_fn_name.to_string());

    // The real number of argument is one less than in the Rust function's
    // signature. The first argument &mut Caller<'_, ScanContext> doesn't
    // count.
    let num_args = func.sig.inputs.len() - 1;

    let public = attr_args.public;
    let export_ident = format_ident!("export__{}", rust_fn_name);
    let exported_fn_ident = format_ident!("WasmExportedFn{}", num_args);
    let args_signature = FuncSignatureParser::new().parse(&func)?;

    let method_of = attr_args
        .method_of
        .as_ref()
        .map_or_else(|| quote! { None}, |m| quote! { Some(#m) });

    let mangled_fn_name = if let Some(ty_name) = attr_args.method_of {
        format!("{ty_name}::{fn_name}{args_signature}")
    } else {
        format!("{fn_name}{args_signature}")
    };

    let fn_descriptor = quote! {
        #[allow(non_upper_case_globals)]
        #[cfg_attr(not(feature = "inventory"), distributed_slice(WASM_EXPORTS))]
        pub(crate) static #export_ident: WasmExport = WasmExport {
            name: #fn_name,
            mangled_name: #mangled_fn_name,
            public: #public,
            rust_module_path: module_path!(),
            method_of: #method_of,
            func: &#exported_fn_ident { target_fn: &#rust_fn_name },
        };

        #[cfg(feature = "inventory")]
        inventory::submit! {
            WasmExport {
                name: #fn_name,
                mangled_name: #mangled_fn_name,
                public: #public,
                rust_module_path: module_path!(),
                method_of: #method_of,
                func: &#exported_fn_ident { target_fn: &#rust_fn_name },
            }
        }
    };

    let mut token_stream = func.to_token_stream();
    token_stream.extend(fn_descriptor);

    Ok(token_stream)
}

#[cfg(test)]
mod tests {
    use crate::wasm_export::FuncSignatureParser;
    use syn::parse_quote;

    #[test]
    fn func_signature_parser() {
        let mut parser = FuncSignatureParser::new();

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> i32 { 0 }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@i");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> (i32, i32) { (0,0) }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@ii");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>, a: i32, b: i32) -> i32 { a + b }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@ii@i");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> Option<()> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@u");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> Option<i64> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@iu");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> Option<i64> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@iu");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> Option<(i64, f64)> { None }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@ifu");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>)  {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> (i64, RuntimeString) {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@is");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> Lowercase<RuntimeString> {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@s:L");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> Lowercase<FixedLenString<32>> {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@s:N32:L");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> FixedLenString<64> {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@s:N64");

        let func = parse_quote! {
          fn foo(caller: &mut Caller<'_, ScanContext>) -> Option<Lowercase<FixedLenString<32>>> {  }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@s:N32:Lu");
    }
}
