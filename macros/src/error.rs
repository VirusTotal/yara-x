extern crate proc_macro;

use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use quote::{quote, TokenStreamExt};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{
    Attribute, Data, DataEnum, DeriveInput, Error, Expr, Fields, Ident,
    LitStr, Result, Variant,
};

pub(crate) fn impl_error_macro(input: DeriveInput) -> Result<TokenStream> {
    let name = &input.ident;

    let (codes, variants, funcs) = match &input.data {
        Data::Struct(_) | Data::Union(_) => {
            return Err(Error::new(
                name.span(),
                "macros macro Error can be used with only with enum types"
                    .to_string(),
            ))
        }
        Data::Enum(data_enum) => impl_enum_error_macro(data_enum)?,
    };

    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();

    Ok(quote! {
        use yansi::Color;

        #[automatically_derived]
        impl #impl_generics #name #ty_generics #where_clause {
            #(#funcs)*
        }

        #[automatically_derived]
        impl #impl_generics #name #ty_generics #where_clause {
            /// Returns a unique error code identifying the type of error/warning.
            pub fn code(&self) -> &'static str {
                match self {
                    #(Self::#variants { .. } => {
                        #codes
                    })*,
                }
            }

            fn is_valid_code(code: &str) -> bool {
                Self::all_codes().iter().any(|c| *c == code)
            }

            fn all_codes() -> &'static [&'static str] {
                &[ #( #codes, )* ]
            }
        }

        #[automatically_derived]
        impl #impl_generics Display for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(Self::#variants { detailed_report, .. })|* => {
                         write!(f, "{}", detailed_report)
                    }
                }
            }
        }

        #[automatically_derived]
        impl #impl_generics Debug for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(Self::#variants { detailed_report, .. })|* => {
                         write!(f, "{}", detailed_report)
                    }
                }
            }
        }

        #[automatically_derived]
        impl #impl_generics std::error::Error for #name #ty_generics #where_clause {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                None
            }
        }
    })
}

fn impl_enum_error_macro(
    data_enum: &DataEnum,
) -> Result<(Vec<LitStr>, Vec<&Ident>, Vec<TokenStream>)> {
    // Generate a function for each variant in the enum labelled
    // with #[error(...)] or #[warning(...)].
    let mut funcs = Vec::new();
    let mut variants = Vec::new();
    let mut codes = Vec::new();
    // For each variant in the enum...
    for variant in &data_enum.variants {
        // ...look for #[error(...)] or #[warning(...)] attribute.
        for attr in &variant.attrs {
            if let Some((kind, error_attr)) = parse_attr(attr)? {
                variants.push(&variant.ident);
                funcs.push(gen_build_func(
                    kind,
                    &error_attr.code,
                    &error_attr.description,
                    variant,
                )?);
                codes.push(error_attr.code);
            }
        }
    }
    Ok((codes, variants, funcs))
}

#[derive(Debug)]
struct ErrorArgs {
    code: LitStr,
    description: LitStr,
}

impl Parse for ErrorArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut args = Punctuated::<LitStr, Comma>::parse_terminated(input)?;

        if args.len() != 2 {
            return Err(
                Error::new_spanned(
                    args,
                    "#[error(...)] must have exactly 2 arguments: code and description".to_string(),
                ));
        }

        let description = args.pop().unwrap().into_value();
        let code = args.pop().unwrap().into_value();

        Ok(ErrorArgs { code, description })
    }
}

// Checks if an attribute is #[error(...)] or #[warning(...)] and returns its
// arguments. Otherwise, it returns None.
fn parse_attr(attr: &Attribute) -> Result<Option<(&'static str, ErrorArgs)>> {
    let kind = if attr.path().is_ident("error") {
        "error"
    } else if attr.path().is_ident("warning") {
        "warning"
    } else {
        return Ok(None);
    };

    let args = attr.meta.require_list()?.parse_args::<ErrorArgs>()?;

    Ok(Some((kind, args)))
}

// Given an error or warning variant, generates the function that builds
// an instance of this error or warning.
fn gen_build_func(
    kind: &str,
    code: &LitStr,
    description: &LitStr,
    variant: &Variant,
) -> Result<TokenStream> {
    match &variant.fields {
        Fields::Named(fields) => {
            // Each error variant has one or more labels (e.g. #[label(...)]),
            // get the labels for this variant.
            let labels = get_labels(variant)?;

            // The variant can also have a note (e.g. #[note(...)]).
            let note = get_note(variant)?;

            // The main label is the first label in the tuple.
            let main_label = &labels.first().ok_or_else(|| {
                Error::new_spanned(
                    variant,
                    "#[error(...)] must be accompanied by at least one instance of #[label(...)}",
                )})?;

            // The span identifier is the first item in the tuples returned
            // by get_labels.
            let main_label_span = &main_label.0;

            // The arguments to the function have the same names and types as
            // the fields in the struct variant. Except for the field named
            // `detailed_report`, which is not included in the arguments.
            let mut args = TokenStream::new();
            args.append_all(
                fields
                    .named
                    .pairs()
                    .filter(
                        |pair| *pair.value().ident.as_ref().unwrap() != "detailed_report"
                    ),
            );

            let field_identifiers =
                fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().unwrap());

            let variant_ident = &variant.ident;
            let fn_ident = Ident::new(
                &variant_ident.to_string().to_case(Case::Snake), Span::call_site());

            // Labels is a vector of tuples (Ident, TokenStream), convert it
            // to a vector of TokenStream, Idents are dropped.
            let labels = labels.iter().map(|(_, labels)| labels);

            let report_type = match kind {
                "error" => quote!(Level::Error),
                "warning" => quote!(Level::Warning),
                _  => unreachable!(),
            };

            Ok(quote!(
                #[doc(hidden)]
                pub fn #fn_ident(report_builder: &ReportBuilder, #args) -> Self {
                    use crate::compiler::report::SourceRef;
                    let detailed_report = report_builder.create_report(
                        #report_type,
                        &#main_label_span,
                        #code,
                        &format!(#description),
                        vec![
                            #( #labels ),*
                        ],
                        #note.clone(),
                    );
                    Self::#variant_ident{
                        #( #field_identifiers ),*
                    }
                }
            ))
        }
        Fields::Unnamed(_) | Fields::Unit => {
            Err(Error::new_spanned(
                variant,
                format!(
                    "{} not a struct variant, #[error(...)] can be used only with struct variants",
                    variant.ident
                ),
            ))
        }
    }
}

fn get_note(variant: &Variant) -> Result<TokenStream> {
    // Try to find a #[note(...)] attribute.
    let note_attr =
        match variant.attrs.iter().find(|attr| attr.path().is_ident("note")) {
            Some(attr) => attr,
            None => return Ok(quote!(None)),
        };

    // Let's check that it has a list of arguments...
    let args = note_attr.meta.require_list()?;

    // The arguments are a comma-separated list of expressions.
    let args =
        args.parse_args_with(Punctuated::<Expr, Comma>::parse_terminated)?;

    // It should have exactly one argument, which is the field that
    // contains the note.
    if args.len() != 1 {
        return Err(Error::new_spanned(
            args,
            "#[note(...)] must receive exactly one argument",
        ));
    }

    let node_field = &args[0];

    // Make sure that label_span_field it's an identifier.
    let node_field = match node_field {
        Expr::Path(expr) => expr.path.get_ident(),
        _ => None,
    };

    let node_field = node_field.ok_or_else(|| {
        Error::new_spanned(
            node_field,
            format!(
                "the argument for #[note(...)] must be a field in `{}`",
                variant.ident
            ),
        )
    })?;

    Ok(quote!(#node_field))
}

fn get_labels(variant: &Variant) -> Result<Vec<(Ident, TokenStream)>> {
    let mut labels = Vec::new();

    // Iterate over the #[label_xxxx(...)] attributes.
    for attr in variant.attrs.iter().filter(|attr| {
        attr.path().is_ident("label_error")
            || attr.path().is_ident("label_warn")
            || attr.path().is_ident("label_info")
            || attr.path().is_ident("label_note")
            || attr.path().is_ident("label_help")
    }) {
        // Check that the attribute has a list of arguments.
        let args = attr.meta.require_list()?;

        // The arguments are a comma-separated list of expressions.
        let args =
            args.parse_args_with(Punctuated::<Expr, Comma>::parse_terminated)?;

        // It should have two arguments, the first argument should be the
        // label's format string, and the second argument is the name of the
        // field that contains the span for the label.
        if args.len() != 2 {
            return Err(Error::new_spanned(
                args,
                "#[label_xxxx(...)] must receive two arguments",
            ));
        }

        let label_fmt = &args[0];
        let label_span_field = &args[1];

        // Make sure that label_span_field it's an identifier.
        let label_span_field = match label_span_field {
            Expr::Path(expr) => expr.path.get_ident(),
            _ => None,
        };

        let label_span_field = label_span_field.ok_or_else(|| {
            Error::new_spanned(
                label_span_field,
                format!(
                    "the second argument for #[label_xxxx(...)] must be a field in `{}`",
                    variant.ident
                ),
            )
        })?;

        // Also make sure that the field actually exists in the structure.
        if !variant
            .fields
            .iter()
            .any(|field| field.ident.as_ref() == Some(label_span_field))
        {
            return Err(Error::new_spanned(
                label_span_field,
                format!(
                    "field `{}` not found in `{}`",
                    label_span_field, variant.ident
                ),
            ));
        }

        let level = if attr.meta.path().is_ident("label_warn") {
            quote!(Level::Warning)
        } else if attr.meta.path().is_ident("label_info") {
            quote!(Level::Info)
        } else if attr.meta.path().is_ident("label_note") {
            quote!(Level::Note)
        } else if attr.meta.path().is_ident("label_help") {
            quote!(Level::Help)
        } else {
            quote!(Level::Error)
        };

        labels.push((
            label_span_field.clone(),
            quote!(
                (&#label_span_field, format!(#label_fmt), #level)
            ),
        ));
    }

    Ok(labels)
}
