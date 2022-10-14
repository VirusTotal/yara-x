extern crate proc_macro;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// The HasSpan derive macro implements the [`HasSpan`] trait for structs and
/// enums.
///
/// The struct must have a field named `span` of type [`Span`], and the macro
/// will add to it a `span` method that returns the value from the field with
/// the same name.
///
/// When used with a enum, all variants must be either a struct that has a
/// field named `span` or a single-item tuple where the item implements the
/// [`HasSpan`] trait.
///
/// # Examples
///
/// Using `HasSpan` on a structure. Notice the required `span` field in the
/// structure.
///
/// ```
/// #[derive(Debug, HasSpan)]
/// pub struct LiteralStr<'src> {
///     pub(crate) span: Span,
///     pub value: &'src str,
/// }
/// ```
///
/// Using `HasSpan` on a enum. The `True` variant is a struct that has a `span`
/// field, and the `LiteralInt` variant contains a `Box<LiteralInt>`, which
/// implements the [`HasSpan`] trait.
///
/// ```
/// #[derive(Debug, HasSpan)]
/// pub enum Expr<'src> {
///     // Ok. The struct has a `span` field of type `Span`.
///     True {
///         span: Span,
///     },
///
///     // Ok. It's a single-element tuple where `Box<LiteralInt>` implements
///     // the `HasSpan` trait.
///     LiteralInt(Box<LiteralInt>),
///
///     // Wrong. Unitary variants are not allowed. There's no way for
///     // determining its span.
///     False
/// }
/// ```
///
#[proc_macro_derive(HasSpan)]
pub fn span_macro_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    impl_span_macro(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn impl_span_macro(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let data = &input.data;

    let span_impl = match data {
        syn::Data::Struct(_) => syn::Result::Ok(quote! { self.span }),
        syn::Data::Enum(data_enum) => {
            let mut variants = vec![];

            for pair in data_enum.variants.pairs() {
                let ident = &pair.value().ident;
                match &pair.value().fields {
                    syn::Fields::Named(_) => variants.push(quote!(Self::#ident{span, ..} => *span)),
                    syn::Fields::Unnamed(_) => variants.push(quote!(Self::#ident(x) => x.span())),
                    syn::Fields::Unit => {
                        return Err(syn::Error::new_spanned(
                            &pair,
                            format!(
                                "can't derive the `HasSpan` trait for unitary variant `{ident}`"
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
        _ => panic!("HasSpan derive macro can be used only with structs and enums"),
    }?;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    syn::Result::Ok(quote! {
        #[automatically_derived]
        impl #impl_generics HasSpan for #name #ty_generics #where_clause {
            fn span(&self) -> Span {
                #span_impl
            }
        }
    })
}
