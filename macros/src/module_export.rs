use darling::FromMeta;
use proc_macro2::TokenStream;
use quote::{ToTokens, format_ident, quote};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{Expr, FnArg, ItemFn, Pat, Result};

#[derive(Debug, FromMeta)]
/// Arguments received by the `#[module_export]` macro.
pub struct ModuleExportsArgs {
    name: Option<String>,
    method_of: Option<String>,
    sync: Option<String>,
    /// When set, the macro is being invoked from an external crate. Generated
    /// thunk code uses fully qualified types from this crate path, and passes
    /// `yara_x_crate` through to the inner `#[wasm_export]`.
    yara_x_crate: Option<String>,
}

/// Implementation for the `#[module_export]` attribute macro.
///
/// This attribute is used for exporting functions from YARA modules, to make
/// them callable from rules. The implementation is just a thin layer on top
/// of `#[wasm_export]` that simply adds an intermediate function converts the
/// argument `caller: &mut Caller<'_, ScanContext>` into `ctx: &ScanContext`.
///
/// # Example
///
/// Suppose that our function is:
///
/// ```text
/// #[module_export]
/// fn add(ctx: &ScanContext, a: i64, b: i64) -> i64 {
///     a + b
/// }
/// ```
///
/// The code generated will be:
///
/// ```text
/// use wasmtime::Caller;
///
/// #[wasm_export(path = "add")]
/// fn __thunk__add(caller: &mut Caller<'_, ScanContext>, a: i64, b: i64) -> i64 {
///   add(caller.data_mut(), a, b)
/// }
///
/// fn add(ctx: &ScanContext, a: i64, b: i64) -> i64 {
///   a + b
/// }
/// ```
pub(crate) fn impl_module_export_macro(
    attr_args: Vec<darling::ast::NestedMeta>,
    mut func: ItemFn,
) -> Result<TokenStream> {
    let attr_args = ModuleExportsArgs::from_list(attr_args.as_slice())?;

    // Include the original function in the output without changes.
    let mut token_stream = quote! {
        #func
    }
    .to_token_stream();

    // Create new arguments that are exactly the same arguments in the
    // original function, except the first one which changes from
    // `&ScanContext` to `&mut Caller<'_, ScanContext>`.
    let mut fn_args: Punctuated<FnArg, Comma> = Punctuated::new();

    // When invoked from an external crate, qualify Caller and ScanContext
    // with the crate path so they resolve correctly outside yara_x.
    let yara_x_crate = attr_args.yara_x_crate;
    let caller_arg = if let Some(ref crate_str) = yara_x_crate {
        let crate_path: syn::Path = syn::parse_str(crate_str).unwrap();
        syn::parse2(quote! {
            caller: &mut #crate_path::Caller<'_, #crate_path::ScanContext<'_, '_>>
        })?
    } else {
        syn::parse2(quote! {
            caller: &mut Caller<'_, ScanContext>
        })?
    };
    fn_args.push(caller_arg);

    fn_args.extend(func.sig.inputs.into_iter().skip(1));

    let mut arg_pats: Punctuated<Expr, Comma> = Punctuated::new();

    for arg in fn_args.iter().skip(1).cloned() {
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

    let rust_fn_name = func.sig.ident;
    let fn_name = attr_args.name.unwrap_or(rust_fn_name.to_string());
    let sync = attr_args.sync.unwrap_or_else(|| "none".to_owned());
    let method_of = attr_args.method_of;

    // Modify the original function and convert it into the thunk function.
    func.sig.ident = format_ident!("__thunk__{}", rust_fn_name);
    func.sig.inputs = fn_args;

    func.block = syn::parse2(quote! {{
        #rust_fn_name(caller.data_mut(), #arg_pats)
    }})
    .unwrap();

    let wasm_export = match (&yara_x_crate, &method_of) {
        (Some(crate_str), Some(m)) => {
            let crate_path: syn::Path = syn::parse_str(crate_str).unwrap();
            quote! { #[#crate_path::wasm_export(yara_x_crate = #crate_str, name = #fn_name, public = true, method_of = #m, sync = #sync)] }
        }
        (Some(crate_str), None) => {
            let crate_path: syn::Path = syn::parse_str(crate_str).unwrap();
            quote! { #[#crate_path::wasm_export(yara_x_crate = #crate_str, name = #fn_name, public = true, sync = #sync)] }
        }
        (None, Some(m)) => {
            quote! { #[wasm_export(name = #fn_name, public = true, method_of = #m, sync = #sync)] }
        }
        (None, None) => {
            quote! { #[wasm_export(name = #fn_name, public = true, sync = #sync)] }
        }
    };

    // Add the thunk function to the output.
    token_stream.extend(quote! {
        #wasm_export
        #[inline(always)]
        #[allow(non_snake_case)]
        #func
    });

    Ok(token_stream)
}
