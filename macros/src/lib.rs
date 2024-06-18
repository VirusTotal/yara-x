use proc_macro::TokenStream;
use syn::{parse_macro_input, AttributeArgs, DeriveInput, ItemFn};

mod error;
mod module_export;
mod module_main;
mod span;
mod wasm_export;

/// The `HasSpan` derive macro implements the [`HasSpan`] trait for structs and
/// enums.
///
/// The struct must have a field named `span` of type `Span`, and the macro
/// will add to it a `span` method that returns the value from the field with
/// the same name.
///
/// When used with an enum, all variants must be either a struct that has a
/// field named `span` or a single-item tuple where the item implements the
/// [`HasSpan`] trait.
///
/// # Examples
///
/// Using `HasSpan` on a structure. Notice the required `span` field in the
/// structure.
///
/// ```text
/// #[macros(Debug, HasSpan)]
/// pub struct LiteralStr<'src> {
///     pub(crate) span: Span,
///     pub value: &'src str,
/// }
/// ```
///
/// Using `HasSpan` on an enum. The `True` variant is a struct that has a `span`
/// field, and the `LiteralInt` variant contains a `Box<LiteralInt>`, which
/// implements the [`HasSpan`] trait.
///
/// ```text
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
/// error[E100]: duplicate tag `tag1`
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
/// `#[warning(...)]`, both of these tags receive two arguments: code and
/// description. The code is a string that uniquely identify the error,
/// like "E201", and the description is a brief text describing the error.
///
/// ```text
/// #[derive(Error)]
/// pub enum Error {
///    #[error("E102", "duplicate tag `{tag}`")]
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
/// type `Span` in the structure. The label will be associated to the code
/// span indicated by that field.
///
/// In the example above we use `#[label("duplicate tag", tag_span)]` for
/// creating a label with the text "duplicate tag" associated to the span
/// indicated in `tag_span`. You can specify more than one label if
/// necessary.
///
/// For changing the style of a label you can use `style="style"` as an
/// optional last argument. For example:
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
/// Also, the first argument for the function is always `&ReportBuilder`.
///
/// So, the function for the `DuplicateTag` example above will be...
///
/// ```text
/// duplicate_tag(
///     report_builder: &ReportBuilder,
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
/// The main function in a YARA module receives a slice that contains the
/// data being scanned, and must return the protobuf structure that corresponds
/// to the module. The function can have any name, as long as it is marked with
/// `#[module_main]`, but it's a good practice to name it `main`.
///
/// # Example
///
/// ```text
/// #[module_main]
/// fn main(data: &[u8]) -> SomeProto {   
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

/// The `wasm_export` macro is used for declaring a Rust function that will be
/// called from WASM.
///
/// The function's first argument must be of type `wasmtime::Caller`, which
/// contains information about the context in which the function is called,
/// including a reference to the `yara_x::scanner::ScanContext` corresponding
/// to the current scan.
///
/// The rest of the arguments, if any, must be of any of the following types:
///
/// - `i32`
/// - `i64`
/// - `f32`
/// - `f64`
/// - `bool`
/// - `RuntimeString`
/// - `RuleId`
/// - `PatternId`
/// - `Rc<Struct>`
/// - `Rc<Map>`
/// - `Rc<Array>`
///
/// # Example
///
/// ```text
/// #[wasm_export]
/// fn add(caller: Caller<'_, ScanContext>, a: i64, b: i64) -> i64 {   
///     a + b
/// }
/// ```
///
/// Optionally, the `wasm_export` macro can receive the name used for exporting
/// the function. If not specified, the function will be exported with the name
/// it has in the Rust code, but you can specify a different name. This allow
/// having multiple functions with the same name, as long as their signatures
/// are different.
///
/// # Example
///
/// ```text
/// use wasmtime::Caller;
///
/// #[wasm_export(name = "add")]
/// fn add_i64(caller: Caller<'_, ScanContext>, a: i64, b: i64) -> i64 {   
///     a + b
/// }
///
/// #[wasm_export(name = "add")]
/// fn add_f64(caller: Caller<'_, ScanContext>, a: f64, b: f64) -> f64 {   
///      a + b
/// }
/// ```
///
/// The macro can also receive a `public` argument, which specifies that the
/// function will be visible from YARA rules.
///
/// # Example
///
/// ```text
/// #[wasm_export(public = true)]
/// fn uint8(caller: Caller<'_, ScanContext>, offset: i64) -> i64 {
///   ...
/// }
/// ```
#[proc_macro_attribute]
pub fn wasm_export(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input = parse_macro_input!(input as ItemFn);
    wasm_export::impl_wasm_export_macro(args, input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Indicates that a function is exported from a YARA module and therefore
/// it's callable from YARA rules.
///
/// The function's first argument must be of a mutable or immutable reference
/// to `ScanContext`. The rest of the arguments, if any, can be of any of
/// the following types:
///
/// - `i32`
/// - `i64`
/// - `f32`
/// - `f64`
/// - `bool`
/// - `RuntimeString`
///
/// Optionally, `module_export` can receive the path of the function within
/// the module's structure, like in `#[module_export(foo)]` and
/// `#[module_export(foo.bar)]`.
///
/// # Examples
///
/// Using `#[module_export]` without arguments. The function will be exported
/// with name `add` at the module's top-level structure (i.e: if the module
/// is named `my_module`, the function is invoked as `my_module.add`):
///
/// ```text
/// #[module_export]
/// fn add(ctx: &ScanContext, a: i64, b: i64) -> i64 {   
///     a + b
/// }
/// ```
///
/// Passing the function name to `#[module_export]` and using the same name
/// with two functions that have different signatures. Both functions will
/// be called as `my_module.add`, YARA chooses which one to call based on
/// the type of the arguments:
///
/// ```text
/// #[module_export(add)]
///  fn add_i64(ctx: &ScanContext, a: i64, b: i64) -> i64 {
///   a + b
/// }
///
/// #[module_export(add)]
/// fn add_f64(ctx: &ScanContext, a: f64, b: f64) -> f64 {   
///     a + b
/// }
/// ```
///
/// Passing a path to `#[module_export]`. The function will be called as
/// `my_module.my_struct.add`. The module must have a field `my_struct`
/// of struct type.
///
/// ```text
/// #[module_export(my_struct.add)]
///  fn add(ctx: &ScanContext, a: i64, b: i64) -> i64 {
///   a + b
/// }
/// ```
#[proc_macro_attribute]
pub fn module_export(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input = parse_macro_input!(input as ItemFn);
    module_export::impl_module_export_macro(args, input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
