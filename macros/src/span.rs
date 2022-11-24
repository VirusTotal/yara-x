extern crate proc_macro;
use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

pub(crate) fn impl_span_macro(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let data = &input.data;

    let span_impl = match data {
        syn::Data::Struct(_) => syn::Result::Ok(quote! { self.span }),
        syn::Data::Enum(data_enum) => {
            let mut variants = Vec::new();

            for pair in data_enum.variants.pairs() {
                let ident = &pair.value().ident;
                match &pair.value().fields {
                    syn::Fields::Named(_) => variants.push(quote!(Self::#ident{span, ..} => *span)),
                    syn::Fields::Unnamed(_) => variants.push(quote!(Self::#ident(x) => x.span())),
                    syn::Fields::Unit => {
                        return Err(syn::Error::new_spanned(
                            &pair,
                            format!(
                                "can't macros the `HasSpan` trait for unitary variant `{ident}`"
                            ),
                        ))
                    }
                }
            }

            syn::Result::Ok(quote! {
                match self {
                    #(#variants),*
                }
            })
        }
        _ => panic!(
            "HasSpan macros macro can be used only with structs and enums"
        ),
    }?;

    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();

    syn::Result::Ok(quote! {
        #[automatically_derived]
        impl #impl_generics HasSpan for #name #ty_generics #where_clause {
            fn span(&self) -> Span {
                #span_impl
            }
        }
    })
}
