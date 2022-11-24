use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput, ItemFn};

mod error;
mod module_main;
mod span;

/// The `HasSpan` derive macro implements the [`HasSpan`] trait for structs and
/// enums.
///
/// The struct must have a field named `span` of type `Span`, and the macro
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
/// #[macros(Debug, HasSpan)]
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
/// #[macros(Debug, HasSpan)]
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
pub fn span_macro_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    span::impl_span_macro(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The `Error` derive macro generates boilerplate code for YARA error types.
///
/// This macro can be applied only to enums with struct-like variants. It
/// won't work if the enum contains unit-like or tuple-like variants. Each
/// variant in the enum must have a `detailed_report` field of [`String`]
/// type. This field will contain fully detailed error message, like
/// this one...
///
/// ```text
/// error: duplicate tag `tag1`
///    ╭─[line:1:18]
///    │
///  1 │ rule test : tag1 tag1 { condition: true }
///    ·                  ──┬─  
///    ·                    ╰─── duplicate tag
/// ───╯
/// ```
///
/// The rest of the fields vary from variant to variant. But they usually
/// contain information that is used for rendering the detailed report.
///
/// Each variant in the enum must be tagged with `#[error(...)]` or
/// `#[warning(...)]` where the arguments inside the parenthesis are directly
/// passed to [`format!`] for building the error/warning title. For example...
///
/// ```
/// #[macros(Error)]
/// pub enum Error {
///    #[error("duplicate tag `{tag}`")]
///    #[label("duplicate tag", tag_span)]
///    DuplicateTag {
///      detailed_report: String,
///      tag: String,
///      tag_span: Span,
///    },
/// }
/// ```
///
/// Notice how the placeholder {tag} is used for building an error title that
/// takes the name of the tag from the `tag` field in the structure. So, if
/// the value for the `tag` field is `foo`, the error title will be
/// "duplicate rule `foo`"
///
/// In addition to `#[error(...)]` or `#[warning(...)]`, each variant must
/// also have at least one label, defined with `#[label(...)]`. The arguments
/// passed to `#[label(...)]` are also passed to [`format!`] for creating a
/// label, except for the last one, which should be the name of a field of
/// type `Span` in the structure. The label will associated to the code
/// span indicated by that field.
///
/// In the example above we use `#[label("duplicate tag", tag_span)]` for
/// creating a label with the text "duplicate tag" asociated to the span
/// indicated in `tag_span`. You can specify more than one label if
/// necessary.
///
/// For changing the style of a label you can use the `style="<style>" as
/// an optional last argument. For example:
///
/// `#[label("duplicate tag", tag_span, style="note")]`
///
/// Valid styles are: "error", "warning" and "note", the default one is
/// "error" for labels accompanied by `#[error(...)]` and "warning" for
/// those accompanied by `#[warning(...)]`.
///
/// Also, for each variant a new function for creating instances of that
/// variant is automatically generated. The functions have a name similar to
/// the variant, but using snake-case instead of camel-case. For example, for
/// variant `DuplicateTag` the function would be named `duplicate_tag`.
///
/// Each function receives as arguments the fields declared in the
/// corresponding structure, with the same names and types. Except for the
/// `detailed_report` field, which won't appear in the function arguments.
/// Also, the first two arguments for the function are always
/// `&ReportBuilder`, and `&SourceCode`.
///
/// So, the function for the `DuplicateTag` example above will be...
///
/// ```
/// duplicate_tag(
///     report_builder: &ReportBuilder,
///     src: &SourceCode,
///     tag: String,
///     tag_span: Span) -> Error
/// ```
#[proc_macro_derive(Error, attributes(error, warning, label, note))]
pub fn error_macro_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    error::impl_error_macro(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The `module_main` macro is used for indicating which is the main function
/// in a YARA module.
///
/// The main function in a YARA module must receive a single argument of
/// type `&ScanContext`, and must return the protobuf structure that corresponds
/// to the module. The function can have any name, as long as it is marked with
/// `#[module_main]`, but it's a good practice to name it `main`.
///
/// # Example
///
/// ```
/// #[module_main]
/// fn main(ctx: &ScanContext) -> SomeProto {   
///     let some_proto = SomeProto::new();
///     // ... fill some_proto with data ...
///     some_proto
/// }
/// ```
#[proc_macro_attribute]
pub fn module_main(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);
    module_main::impl_module_main_macro(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
