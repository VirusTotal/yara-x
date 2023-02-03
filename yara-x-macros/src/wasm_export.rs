extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use std::collections::vec_deque::VecDeque;
use syn::punctuated::Punctuated;
use syn::token::Dot;
use syn::visit::Visit;
use syn::{
    GenericArgument, Ident, ItemFn, PatType, PathArguments, ReturnType, Type,
};

/// Parses signature of a Rust function and returns its
struct FuncSignatureParser<'ast> {
    arg_types: Option<VecDeque<&'ast Type>>,
}

impl<'ast> FuncSignatureParser<'ast> {
    fn new() -> Self {
        Self { arg_types: None }
    }

    fn rust_type_to_mangled(ty: &str) -> &str {
        match ty {
            "i32" | "i64" => "i",
            "f32" | "f64" => "f",
            "PatternId" | "RuleId" => "i",
            "bool" => "b",
            "RuntimeString" => "s",
            _ => unreachable!("unknown type: {}", ty),
        }
    }

    fn parse(&mut self, func: &'ast syn::ItemFn) -> syn::Result<String> {
        self.arg_types = Some(VecDeque::new());

        // This loop traverses the function arguments' AST, populating
        // `self.arg_types`.
        for fn_arg in func.sig.inputs.iter() {
            self.visit_fn_arg(fn_arg);
        }

        let mut arg_types = self.arg_types.take().unwrap();

        // Make sure that the first argument is `Caller`.
        let first_argument_is_ok = if let Some(ty) = arg_types.pop_front() {
            Self::extract_type_ident(ty)?.map_or(false, |type_ident| {
                type_ident.to_string().as_str() == "Caller"
            })
        } else {
            false
        };

        if !first_argument_is_ok {
            return Err(syn::Error::new_spanned(
                &func.sig,
                format!(
                    "the first argument for function `{}` must be `Caller<'_, ScanContext>`",
                    func.sig.ident),
            ));
        }

        let mut mangled_named = String::from("@");

        for arg_type in arg_types {
            mangled_named.push_str(Self::rust_type_to_mangled(
                Self::extract_type_ident(arg_type)?
                    .unwrap()
                    .to_string()
                    .as_str(),
            ));
        }

        if let ReturnType::Type(.., return_type) = &func.sig.output {
            let mut type_ident = Self::extract_type_ident(return_type)?;
            let mut maybe_undef = false;

            // If the result type is MaybeUndef<T>, type_ident will be "T"
            // and maybe_undef is set to true.
            while let Some(t) = type_ident {
                if t == "MaybeUndef" {
                    maybe_undef = true;
                    if let Type::Path(path) = return_type.as_ref() {
                        if let PathArguments::AngleBracketed(angle_bracketed) =
                            &path.path.segments.last().unwrap().arguments
                        {
                            if let GenericArgument::Type(ty) =
                                angle_bracketed.args.first().unwrap()
                            {
                                type_ident = Self::extract_type_ident(ty)?;
                            }
                        }
                    }
                } else {
                    break;
                }
            }

            if let Some(t) = type_ident {
                mangled_named.push('@');
                mangled_named.push_str(Self::rust_type_to_mangled(
                    t.to_string().as_str(),
                ));

                if maybe_undef {
                    mangled_named.push('u');
                }
            }
        }

        Ok(mangled_named)
    }

    fn extract_type_ident(ty: &syn::Type) -> syn::Result<Option<&syn::Ident>> {
        match ty {
            Type::Path(path) => {
                Ok(Some(&path.path.segments.last().unwrap().ident))
            }
            Type::Group(group) => {
                Self::extract_type_ident(group.elem.as_ref())
            }
            Type::Tuple(tuple) => {
                if tuple.elems.is_empty() {
                    Ok(None)
                } else {
                    Err(syn::Error::new_spanned(
                        ty,
                        "can not return or receive this type",
                    ))
                }
            }
            _ => Err(syn::Error::new_spanned(
                ty,
                "can not return or receive this type",
            )),
        }
    }
}

impl<'ast> Visit<'ast> for FuncSignatureParser<'ast> {
    fn visit_pat_type(&mut self, pat_type: &'ast PatType) {
        self.arg_types.as_mut().unwrap().push_back(pat_type.ty.as_ref());
    }
}

/// Implementation for the `#[wasm_export]` attribute macro.
///
/// This attribute is used in functions that will be called from WASM.
/// For each function using this attribute the macro adds an entry to the
/// `WASM_EXPORTS` global slice. This is done by adding a code snippet
/// similar to the one shown below.
///
/// # Example
///
/// Suppose that our function is:
///
/// ```text
/// #[wasm_export]
/// fn add(caller: Caller<'_, ScanContext>, a: i64, b: i64) -> i64 {   
///     a + b
/// }
/// ```
///
/// The code generated will be:
///
/// ```text
/// #[distributed_slice(WASM_EXPORTS)]
/// static __export__add: WasmExport = WasmExport {
///     name: "add",
///     mangled_name: "add@ii@i",
///     rust_module_path: "yara_x::modules::my_module",
///     func: &WasmExportedFn2 { target_fn: &add },
/// };
/// ```
///
/// Notice that the generated code uses `WasmExportedFn2` because the function
/// receives two parameters (not counting `caller: Caller<'_, ScanContext>`)
///
pub(crate) fn impl_wasm_export_macro(
    name: Punctuated<Ident, Dot>,
    func: ItemFn,
) -> syn::Result<TokenStream> {
    let fn_name = &func.sig.ident;

    let fn_name_str = if name.is_empty() {
        fn_name.to_string()
    } else {
        name.to_token_stream().to_string()
    };

    if func.sig.inputs.is_empty() {
        return Err(syn::Error::new_spanned(
            &func.sig,
            format!(
                "function `{}` must have at least one argument of type `Caller<'_, ScanContext>`", 
                fn_name),
        ));
    }

    let num_args = func.sig.inputs.len() - 1;

    let export_ident = format_ident!("__export__{}", fn_name);
    let exported_fn_ident = format_ident!("WasmExportedFn{}", num_args);

    let mut func_sig_parser = FuncSignatureParser::new();

    let mangled_fn_name =
        format!("{}{}", fn_name_str, func_sig_parser.parse(&func)?);

    let fn_descriptor = quote! {
        #[allow(non_upper_case_globals)]
        #[distributed_slice(WASM_EXPORTS)]
        static #export_ident: WasmExport = WasmExport {
            name: #fn_name_str,
            mangled_name: #mangled_fn_name,
            rust_module_path: module_path!(),
            func: &#exported_fn_ident { target_fn: &#fn_name },
        };
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
          fn foo(caller: Caller<'_, ScanContext>) -> i32 { 0 }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@@i");

        let func = parse_quote! {
          fn foo(caller: Caller<'_, ScanContext>, a: i32, b: i32) -> i32 { a + b }
        };

        assert_eq!(parser.parse(&func).unwrap(), "@ii@i");
    }
}
