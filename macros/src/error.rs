extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{Data, DeriveInput, Error, Expr, Field, Ident, LitStr, Result};

/// Describes a label in an error/warning message.
#[derive(Debug)]
struct Label {
    label_fmt: LitStr,
    label_ref: Ident,
    level: Option<Expr>,
}

impl Parse for Label {
    /// Parses a label like the one below.
    ///
    /// ```text
    /// #[label("{error_msg}", error_ref, Level::Info)]
    /// ```
    ///
    /// The last argument is optional, the default value is `Level::Error`.
    fn parse(input: ParseStream) -> Result<Self> {
        let label_fmt: LitStr = input.parse()?;
        let _ = input.parse::<Comma>()?;
        let label_ref: Ident = input.parse()?;
        let mut level = None;
        if input.peek(Comma) {
            input.parse::<Comma>()?;
            level = Some(input.parse::<Expr>()?);
        }
        Ok(Label { label_fmt, label_ref, level })
    }
}

/// Describes a footer in an error/warning message.
#[derive(Debug)]
struct Footer {
    footer_expr: Expr,
    level: Option<Expr>,
}

impl Parse for Footer {
    /// Parses a footer like the one below.
    ///
    /// ```text
    /// #[footer(text, Level::Info)]
    /// ```
    ///
    /// The last argument is optional, the default value is `Level::Note`.
    fn parse(input: ParseStream) -> Result<Self> {
        let footer_expr: Expr = input.parse()?;
        let mut level = None;
        if input.peek(Comma) {
            input.parse::<Comma>()?;
            level = Some(input.parse::<Expr>()?);
        }
        Ok(Footer { footer_expr, level })
    }
}

pub(crate) fn impl_error_struct_macro(
    input: DeriveInput,
) -> Result<TokenStream> {
    let fields =
        match &input.data {
            Data::Struct(s) => &s.fields,
            Data::Enum(_) | Data::Union(_) => return Err(Error::new(
                input.ident.span(),
                "macro ErrorStruct can be used with only with struct types"
                    .to_string(),
            )),
        };

    let mut level = None;
    let mut code = None;
    let mut title = None;
    let mut associated_enum = None;
    let mut labels = Vec::new();
    let mut footers = Vec::new();

    for attr in input.attrs {
        if attr.path().is_ident("doc") {
            // `doc` attributes are ignored, they are actually the
            //  documentation comments added in front of structures.
            continue;
        } else if attr.path().is_ident("associated_enum") {
            associated_enum = Some(attr.parse_args::<Ident>()?);
        } else if attr.path().is_ident("label") {
            labels.push(attr.parse_args::<Label>()?);
        } else if attr.path().is_ident("footer") {
            footers.push(attr.parse_args::<Footer>()?);
        } else {
            if attr.path().is_ident("error") {
                level = Some(quote!(Level::Error))
            } else if attr.path().is_ident("warning") {
                level = Some(quote!(Level::Warning))
            } else {
                return Err(Error::new(
                    attr.path().span(),
                    "unexpected attribute".to_string(),
                ));
            }
            attr.parse_nested_meta(|meta| {
                match meta.path.get_ident() {
                    Some(ident) if ident == "code" => {
                        code = Some(meta.value()?.parse::<LitStr>()?);
                    }
                    Some(ident) if ident == "title" => {
                        title = Some(meta.value()?.parse::<LitStr>()?);
                    }
                    _ => {
                        return Err(Error::new(
                            meta.path.span(),
                            "unknown argument, expecting `code = \"...\", title = \"...\"`".to_string(),
                        ));
                    }
                };
                Ok(())
            })?;
        }
    }

    let associated_enum = match associated_enum {
        Some(e) => e,
        None => {
            return Err(Error::new(
                input.ident.span(),
                "struct doesn't have associated enum, use #[associated_enum(EnumType)]".to_string(),
            ));
        }
    };

    let struct_name = input.ident;

    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();

    let labels = labels.iter().map(|label| {
        let label_fmt = &label.label_fmt;
        let label_ref = &label.label_ref;
        // If a level is explicitly specified as part of the label definition,
        // use the specified level, if not, use Level::Error for #[error(...)]
        // and Level::Warning for #[warning(...)].
        match &label.level {
            Some(level_expr) => {
                quote!((#level_expr, #label_ref.clone(), format!(#label_fmt)))
            }
            None => {
                quote!((#level, #label_ref.clone(), format!(#label_fmt)))
            }
        }
    });

    let footers = footers.iter().map(|footer| {
        let footer_expr = &footer.footer_expr;
        match &footer.level {
            Some(level_expr) => {
                quote!((#level_expr, #footer_expr.clone()))
            }
            None => {
                quote!((Level::Note, #footer_expr.clone()))
            }
        }
    });

    // Get all fields in the structure, except the `report` field.
    let fields: Vec<&Field> = fields
        .iter()
        .filter(|field| {
            field.ident.as_ref().is_some_and(|ident| ident != "report")
        })
        .collect();

    // The function arguments have the same name and type than the fields.
    let fn_args = fields.iter().map(|field| {
        let name = field.ident.as_ref().unwrap();
        let ty = &field.ty;
        quote!(#name : #ty)
    });

    // Get the names of the fields.
    let field_names = fields.iter().map(|field| field.ident.as_ref().unwrap());

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #struct_name #ty_generics #where_clause {
            pub(crate) fn build(
                report_builder: &ReportBuilder,
                #( #fn_args ),*
            ) -> #associated_enum {
                #associated_enum::#struct_name(
                    Box::new(Self {
                        report: report_builder.create_report(
                            #level,
                            #code,
                            format!(#title),
                            vec![#( #labels ),*],
                            vec![#( #footers ),*],
                        ),
                        #( #field_names ),*
                    })
                )
            }
        }

        #[automatically_derived]
        impl #impl_generics #struct_name #ty_generics #where_clause {
            /// Returns a unique code identifying the type of error/warning.
            ///
            /// Error codes have the form "Eddd", where "ddd" is an error number
            /// (examples: "E001", "E020"). Warnings have more descriptive codes,
            /// like: "slow_pattern", "unsatisfiable_expr", etc.
            #[inline]
            pub const fn code() -> &'static str {
                #code
            }

            /// Returns the title of this error/warning.
            #[inline]
            pub fn title(&self) -> &str {
                self.report.title()
            }

            /// Returns the labels associated to this error/warning.
            #[inline]
            pub fn labels(&self) -> impl Iterator<Item = Label> {
                self.report.labels()
            }

            /// Returns the footers associated to this error/warning.
            #[inline]
            #[inline]
            pub fn footers(&self) -> impl Iterator<Item = Footer> {
                self.report.footers()
            }
        }

        #[automatically_derived]
        impl #impl_generics std::error::Error for #struct_name #ty_generics #where_clause {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                None
            }
        }

        #[automatically_derived]
        impl #impl_generics Display for #struct_name #ty_generics #where_clause {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.report)
            }
        }

        #[automatically_derived]
        impl #impl_generics serde::Serialize for #struct_name #ty_generics #where_clause {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.report.serialize(serializer)
            }
        }
    })
}

pub(crate) fn impl_error_enum_macro(
    input: DeriveInput,
) -> Result<TokenStream> {
    let variants = match &input.data {
        Data::Enum(s) => &s.variants,
        Data::Struct(_) | Data::Union(_) => {
            return Err(Error::new(
                input.ident.span(),
                "macro ErrorEnum can be used with only with enum types"
                    .to_string(),
            ))
        }
    };

    let variant_idents: Vec<&Ident> =
        variants.iter().map(|variant| &variant.ident).collect();

    let num_variants = variant_idents.len();

    let enum_name = input.ident;

    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();

    Ok(quote!(
        #[automatically_derived]
        impl #impl_generics Debug for #enum_name #ty_generics #where_clause {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(
                        Self::#variant_idents(v) => {
                            write!(f, "{}", v)?;
                        }
                    ),*
                };
                Ok(())
            }
        }

        #[automatically_derived]
        impl #impl_generics Display for #enum_name #ty_generics #where_clause {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(
                        Self::#variant_idents(v) => {
                            write!(f, "{}", v)?;
                        }
                    ),*
                };
                Ok(())
            }
        }

        impl #impl_generics #enum_name #ty_generics #where_clause {
            /// Returns all the existing error or warning codes.
            ///
            /// Error codes have the form "Eddd", where "ddd" is an error number
            /// (examples: "E001", "E020"). Warnings have more descriptive codes,
            /// like: "slow_pattern", "unsatisfiable_expr", etc.
            pub const fn all_codes() -> [&'static str; #num_variants] {
                [
                    #(
                        #variant_idents::code()
                    ),*
                ]
            }

            /// Returns the error code for this error or warning.
            pub fn code(&self) -> &'static str {
                match self {
                    #(
                        Self::#variant_idents(v) => {
                            #variant_idents::code()
                        }
                    ),*
                }
            }

            /// Returns the title of this error/warning.
            #[inline]
            pub fn title(&self) -> &str {
                match self {
                    #(
                        Self::#variant_idents(v) => {
                             v.report.title()
                        }
                    ),*
                }
            }

            /// Returns the labels associated to this error/warning.
            #[inline]
            pub fn labels(&self) -> impl Iterator<Item = Label> {
                 match self {
                    #(
                        Self::#variant_idents(v) => {
                             v.report.labels()
                        }
                    ),*
                 }
            }

            /// Returns the footers associated to this error/warning.
            #[inline]
            pub fn footers(&self) -> impl Iterator<Item = Footer> {
                match self {
                    #(
                        Self::#variant_idents(v) => {
                             v.report.footers()
                        }
                    ),*
                }
            }
        }
    ))
}
