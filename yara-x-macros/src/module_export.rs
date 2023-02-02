use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::punctuated::Punctuated;
use syn::token::{Comma, Dot};
use syn::{Expr, FnArg, Ident, ItemFn, Pat};

/// Implementation for the `#[module_export]` attribute macro.
///
/// This attribute is used for exporting functions from YARA modules, to make
/// them callable from rules. The implementation is just a thin layer on top
/// of `#[wasm_export]` that simply adds an intermediate function converts the
/// argument `caller: Caller<'_, ScanContext>` into `ctx: &ScanContext`.
///
/// # Example
///
/// Suppose that our function is:
///
/// ```no_run
/// #[module_export]
/// fn add(ctx: &ScanContext, a: i64, b: i64) -> i64 {
///     a + b
/// }
/// ```
///
/// The code generated will be:
///
/// ```no_run
/// use wasmtime::Caller;
///
/// #[wasm_export(add)]
/// fn __thunk__add(caller: Caller<'_, ScanContext>, a: i64, b: i64) -> i64 {
///   add(caller.data(), a, b)
/// }
///
/// fn add(ctx: &ScanContext, a: i64, b: i64) -> i64 {
///   a + b
/// }
/// ```
pub(crate) fn impl_module_export_macro(
    name: Punctuated<Ident, Dot>,
    mut func: ItemFn,
) -> syn::Result<TokenStream> {
    let orginal_func = quote! {
        #func
    };

    let mut args: Punctuated<FnArg, Comma> = Punctuated::new();

    args.push(syn::parse2(quote! {
        mut caller: Caller<'_, ScanContext>
    })?);

    args.extend(func.sig.inputs.into_iter().skip(1));

    let mut arg_pats: Punctuated<Expr, Comma> = Punctuated::new();

    for arg in args.iter().skip(1).cloned() {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(ident) = *pat_type.pat {
                arg_pats.push(Expr::Verbatim(quote! {#ident}));
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    let fn_name = func.sig.ident;

    let export_name = format_ident!(
        "{}",
        if name.is_empty() {
            fn_name.to_string()
        } else {
            name.to_token_stream().to_string()
        }
    );

    func.sig.ident = format_ident!("__thunk__{}", fn_name);
    func.sig.inputs = args;
    func.block = syn::parse2(quote! {{
        #fn_name(caller.data_mut(), #arg_pats)
    }})
    .unwrap();

    let thunk_func = quote! {
        #[wasm_export(#export_name)]
        #[inline(always)]
        #[allow(non_snake_case)]
        #func
    };

    let mut token_stream = orginal_func.to_token_stream();
    token_stream.extend(thunk_func);

    Ok(token_stream)
}
