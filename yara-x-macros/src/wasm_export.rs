extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use std::collections::VecDeque;
use syn::visit::Visit;
use syn::{ItemFn, PatType, Type};

/// Parses signature of a Rust function and returns its
struct FuncSignatureParser {
    arg_types: Option<VecDeque<String>>,
}

impl FuncSignatureParser {
    fn new() -> Self {
        Self { arg_types: None }
    }

    fn rust_type_to_mangled(ty: &str) -> &str {
        match ty {
            "i32" | "i64" => "i",
            "f32" | "f64" => "f",
            "PatternId" | "RuleId" => "i",
            "bool" => "b",
            _ => unreachable!("unknown type: {}", ty),
        }
    }

    fn parse(&mut self, func: &ItemFn) -> syn::Result<String> {
        self.arg_types = Some(VecDeque::new());

        // This loop traverses the function arguments' AST, populating
        // `self.arg_types`.
        for fn_arg in func.sig.inputs.iter() {
            self.visit_fn_arg(fn_arg);
        }

        let mut arg_types = self.arg_types.take().unwrap();

        // Make sure that the first argument is `Caller`.
        match arg_types.pop_front().as_deref() {
            Some("Caller") => {}
            _ => {
                return Err(syn::Error::new_spanned(
                    &func.sig,
                    format!(
                        "function `{}` must have at least one argument of type `Caller<'_, ScanContext>`",
                        func.sig.ident),
                ));
            }
        }

        let mut mangled_named = format!("{}@", func.sig.ident);

        for arg_type in arg_types {
            mangled_named
                .push_str(Self::rust_type_to_mangled(arg_type.as_str()));
        }

        mangled_named.push('@');
        mangled_named.push_str(Self::rust_type_to_mangled("i32"));

        Ok(mangled_named)
    }

    fn extract_type_ident(ty: &syn::Type) -> &syn::Ident {
        match ty {
            Type::Path(path) => &path.path.segments.last().unwrap().ident,
            _ => unreachable!(),
        }
    }
}

impl<'ast> Visit<'ast> for FuncSignatureParser {
    fn visit_pat_type(&mut self, pat_type: &'ast PatType) {
        let type_ident = Self::extract_type_ident(pat_type.ty.as_ref());
        self.arg_types.as_mut().unwrap().push_back(type_ident.to_string());
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
    func: ItemFn,
) -> syn::Result<TokenStream> {
    let fn_name = &func.sig.ident;
    let fn_name_str = fn_name.to_string();

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
    let mangled_fn_name = func_sig_parser.parse(&func)?;

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
          fn add(caller: Caller<'_, ScanContext>, a: i32, b: i32) -> i32 { a + b }
        };

        assert_eq!(parser.parse(&func).unwrap(), "add@ii@i");
    }
}
