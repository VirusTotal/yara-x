extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::ItemFn;

pub(crate) fn impl_module_main_macro(
    input: ItemFn,
) -> syn::Result<TokenStream> {
    let fn_name = &input.sig.ident;

    let main_stub = quote! {
        use crate::symbols::ProtoMessage;
        use std::rc::Rc;
        pub(crate) fn __main__(ctx: &ScanContext) -> ProtoMessage {
            ProtoMessage::new(Rc::new(#fn_name(ctx)))
        }
    };

    let mut token_stream = input.to_token_stream();

    token_stream.extend(main_stub);

    syn::Result::Ok(token_stream)
}
