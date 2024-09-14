extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{ItemFn, Result};

pub(crate) fn impl_module_main_macro(input: ItemFn) -> Result<TokenStream> {
    let fn_name = &input.sig.ident;

    let main_stub = quote! {
        use protobuf::MessageDyn;
        pub(crate) fn __main__(data: &[u8], meta: Option<&[u8]>) -> Box<dyn MessageDyn> {
            Box::new(#fn_name(data, meta))
        }
    };

    let mut token_stream = input.to_token_stream();

    token_stream.extend(main_stub);

    Ok(token_stream)
}
