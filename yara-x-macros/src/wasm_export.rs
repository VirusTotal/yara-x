extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::ItemFn;

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

    let fn_descriptor = quote! {
        #[allow(non_upper_case_globals)]
        #[distributed_slice(WASM_EXPORTS)]
        static #export_ident: WasmExport = WasmExport {
            name: #fn_name_str,
            func: &#exported_fn_ident { target_fn: &#fn_name },
        };
    };

    let mut token_stream = func.to_token_stream();
    token_stream.extend(fn_descriptor);

    Ok(token_stream)
}
