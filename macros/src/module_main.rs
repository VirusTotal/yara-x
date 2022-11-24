extern crate proc_macro;

use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens, TokenStreamExt};
use syn::punctuated::Punctuated;
use syn::{
    Attribute, DataEnum, DeriveInput, Ident, ItemFn, Lit, Meta, NestedMeta,
    Token, Variant,
};

pub(crate) fn impl_module_main_macro(
    input: ItemFn,
) -> syn::Result<TokenStream> {
    let fn_name = &input.sig.ident;

    let main_stub = quote! {
        use protobuf::MessageDyn;
        pub(crate) fn __main__(ctx: &ScanContext) -> Box<dyn MessageDyn> {
            Box::new(#fn_name(ctx))
        }
    };

    let mut token_stream = input.to_token_stream();

    token_stream.extend(main_stub);

    syn::Result::Ok(token_stream)
}
