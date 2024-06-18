extern crate proc_macro;

use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens, TokenStreamExt};
use syn::{
    Attribute, DataEnum, DeriveInput, Ident, Lit, Meta, NestedMeta, Variant,
};

pub(crate) fn impl_error_macro(
    input: DeriveInput,
) -> syn::Result<TokenStream> {
    let name = &input.ident;

    let (codes, variants, funcs) = match &input.data {
        syn::Data::Struct(_) | syn::Data::Union(_) => {
            return Err(syn::Error::new(
                name.span(),
                "macros macro Error can be used with only with enum types"
                    .to_string(),
            ))
        }
        syn::Data::Enum(data_enum) => impl_enum_error_macro(data_enum)?,
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
) -> syn::Result<(Vec<NestedMeta>, Vec<&Ident>, Vec<TokenStream>)> {
    // Generate a function for each variant in the enum labelled
    // with #[error(...)] or #[warning(...)].
    let mut funcs = Vec::new();
    let mut variants = Vec::new();
    let mut codes = Vec::new();
    // For each variant in the enum...
    for variant in &data_enum.variants {
        // ...look for #[error(...)] or #[warning(...)] attribute.
        for attr in &variant.attrs {
            if let Some((kind, code, description)) = parse_attr(attr)? {
                variants.push(&variant.ident);
                funcs.push(gen_build_func(
                    kind,
                    &code,
                    &description,
                    variant,
                )?);
                codes.push(code);
            }
        }
    }
    Ok((codes, variants, funcs))
}

// Checks if an attribute is #[error(...)] or #[warning(...)] and returns its
// arguments. Otherwise, it returns None.
fn parse_attr(
    attr: &Attribute,
) -> syn::Result<Option<(&'static str, NestedMeta, NestedMeta)>> {
    let meta = attr.parse_meta()?;

    let kind = if meta.path().is_ident("error") {
        "error"
    } else if meta.path().is_ident("warning") {
        "warning"
    } else {
        return Ok(None);
    };

    let mut attr_args = match meta {
        // `error` and `warning` must be list-style attributes, as in
        // #[error(...)]
        Meta::List(list) => list.nested,
        // any other syntax, like #[error] or #[error = "..."] is not
        // supported.
        _ => {
            return Err(syn::Error::new_spanned(
                meta,
                format!(
                    "expected a list-style attribute (e.g. #[{}(...)])",
                    kind
                ),
            ))
        }
    };

    // There must be exactly 2 arguments, the first one is the error/warning
    // code, and the second one is its description.
    if attr_args.len() != 2 {
        return Err(
            syn::Error::new_spanned(
                attr,
                format!(
                    "#[{}(...)] must have exactly 2 arguments: code and description",
                    kind
                ),
            ));
    }

    // Arguments are popped in reverse order.
    let description = attr_args.pop().unwrap().into_value();
    let code = attr_args.pop().unwrap().into_value();

    Ok(Some((kind, code, description)))
}

// Given an error or warning variant, generates the function that builds
// an instance of this error or warning.
fn gen_build_func(
    kind: &str,
    code: &NestedMeta,
    description: &NestedMeta,
    variant: &Variant,
) -> syn::Result<TokenStream> {
    match &variant.fields {
        syn::Fields::Named(fields) => {
            // Each error variant has one or more labels (e.g. #[label(...)]),
            // get the labels for this variant.
            let labels = get_labels(kind, variant)?;

            // The variant can also have a note (e.g. #[note(...)]).
            let note = get_note(variant)?;

            // The main label is the first label in the tuple.
            let main_label = &labels.first().ok_or_else(|| {
                syn::Error::new_spanned(
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
                    let detailed_report = report_builder.create_report(
                        #report_type,
                        #main_label_span,
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
        syn::Fields::Unnamed(_) | syn::Fields::Unit => {
            Err(syn::Error::new_spanned(
                variant,
                format!(
                    "{} not a struct variant, #[error(...)] can be used only with struct variants",
                    variant.ident
                ),
            ))
        }
    }
}

fn get_note(variant: &Variant) -> syn::Result<TokenStream> {
    // Iterate over the attributes of this variant, looking for #[note(...)]
    for attr in &variant.attrs {
        let meta = attr.parse_meta()?;
        // This attribute is not #[note(...)], skip it and continue iterating.
        if !meta.path().is_ident("note") {
            continue;
        }
        // This is a note attribute, let's check that it has a list of
        // arguments...
        let attr_args = match meta {
            Meta::List(list) => list,
            _ => {
                return Err(syn::Error::new_spanned(
                    meta,
                    "expected a list-style attribute (e.g. #[note(...)])",
                ))
            }
        };
        // It should have exactly one argument, which is the field that
        // contains the note.
        if attr_args.nested.len() != 1 {
            return Err(syn::Error::new_spanned(
                attr_args.nested,
                "#[note(...)] must receive exactly one argument",
            ));
        }

        // Get the argument of #[note(...)], which should be the field that
        // contains the note.
        let note_field = &attr_args.nested.first().unwrap();

        // Make sure that it's an identifier.
        let note_field = match note_field {
            NestedMeta::Meta(Meta::Path(path)) => path.get_ident(),
            _ => None,
        };

        let note_field = note_field.ok_or_else(|| {
            syn::Error::new_spanned(
                note_field,
                format!(
                    "the argument for #[note(...)] must be a field in `{}`",
                    variant.ident
                ),
            )
        })?;

        return Ok(note_field.to_token_stream());
    }

    Ok(quote!(None))
}

fn get_labels(
    kind: &str,
    variant: &Variant,
) -> syn::Result<Vec<(Ident, TokenStream)>> {
    let mut labels = Vec::new();

    // Iterate over the attributes of this variant, looking for #[label(...)]
    for attr in &variant.attrs {
        let meta = attr.parse_meta()?;
        // This attribute is not #[label(...)], skip it and continue iterating.
        if !meta.path().is_ident("label") {
            continue;
        }
        // This is a label attribute, let's check that it has a list of
        // arguments...
        let attr_args = match meta {
            Meta::List(list) => list,
            _ => {
                return Err(syn::Error::new_spanned(
                    meta,
                    "expected a list-style attribute (e.g. #[label(...)])",
                ))
            }
        };
        // It should have at least two arguments, the first argument should be
        // the label's text, which can contain placeholders that are filled
        // with the arguments that follows. The last argument should be the
        // field that contains the span for the label.
        if attr_args.nested.len() < 2 {
            return Err(syn::Error::new_spanned(
                attr_args.nested,
                "#[label(...)] must receive at least two arguments",
            ));
        }

        let mut args = attr_args.nested.pairs();

        // The default label style depends on the type of report. It's red
        // for errors and yellow for warnings.
        let mut level = match kind {
            "error" => quote!(Level::Error),
            "warning" => quote!(Level::Warning),
            _ => unreachable!(),
        };

        // Take the last argument, which should be either the style or the
        // name of the field containing the span for the label.
        let last_arg = args.next_back().unwrap();

        // If the last argument is a named value (e.g. foo = "bar") it can't be
        // the name of the span field, so it should be the style.
        let label_span_field =
            if let NestedMeta::Meta(Meta::NameValue(value)) = last_arg.value()
            {
                // The argument is a named value, but return an error if the
                // name is not "style".
                if !value.path.is_ident("style") {
                    return Err(syn::Error::new_spanned(
                        value,
                        format!(
                            "unknown argument {}",
                            value.path.get_ident().unwrap()
                        ),
                    ));
                }
                // Make sure that the style is a literal string.
                let style_name = match &value.lit {
                    Lit::Str(l) => l.value(),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            value,
                            "argument style must be a string literal",
                        ));
                    }
                };

                // Override the label style with the one specified as an
                // argument. (e.g. #[label(..., style="<style>")]).
                level = match style_name.as_str() {
                    "error" => quote!(Level::Error),
                    "warning" => quote!(Level::Warning),
                    "note" => quote!(Level::Note),
                    s => {
                        return Err(syn::Error::new_spanned(
                            &last_arg,
                            format!("invalid style `{}`", s),
                        ))
                    }
                };

                // Now return the argument next argument from the right, which
                // should be the name of the span field.
                args.next_back().unwrap()
            } else {
                // The last argument is not a named value, so it should be the
                // name of the span field.
                last_arg
            };

        // Make sure that it's an identifier.
        let label_span_field = match label_span_field.value() {
            NestedMeta::Meta(Meta::Path(path)) => path.get_ident(),
            _ => None,
        };

        let label_span_field = label_span_field.ok_or_else(|| {
            syn::Error::new_spanned(
                label_span_field,
                format!(
                    "the second argument for #[label(...)] must be a field in `{}`",
                    variant.ident
                ),
            )
        })?;

        // Also make sure that the field actually exists in the structure.
        let field_found = variant
            .fields
            .iter()
            .any(|field| field.ident.as_ref() == Some(label_span_field));

        if !field_found {
            return Err(syn::Error::new_spanned(
                label_span_field,
                format!(
                    "field `{}` not found in `{}`",
                    label_span_field, variant.ident
                ),
            ));
        }

        let mut label_fmt_args = TokenStream::new();

        for arg in args {
            arg.to_tokens(&mut label_fmt_args);
        }

        labels.push((
            label_span_field.clone(),
            quote!(
                (#label_span_field, format!(#label_fmt_args), #level)
            ),
        ));
    }

    Ok(labels)
}
