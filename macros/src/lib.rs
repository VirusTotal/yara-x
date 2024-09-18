use darling::ast::NestedMeta;
use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput, Error, ItemFn};

mod error;
mod module_export;
mod module_main;
mod wasm_export;

/// The `ErrorStruct` derive macro generates boilerplate code for structs that
/// define YARA errors and warnings.
///
/// Let's see an example:
///
/// ```text
/// #[derive(ErrorStruct)]
/// #[associated_enum(CompileError)]
/// #[error(code = "E021", title = "duplicate tag `{tag}`")]
/// #[label("duplicate tag", loc)]
/// pub struct DuplicateTag {
///    report: Report,
///    tag: String,
///    loc: SourceRef,
/// }
///
/// #[derive(ErrorEnum)]
/// pub enum CompileError {
///    DuplicateTag(DuplicateTag),
///    ... more variants
/// }
/// ```
///
/// Now let's dissect the example line by line:
///
/// ```text
/// #[derive(ErrorStruct)]
/// ```
///
/// 1. The first line is the derive attribute itself.
///
/// ```text
/// #[associated_enum(CompileError)]
/// ```
///
/// 2. The `associated_enum` attribute indicates the name of an enum type that
///    contains a variant for each error/warning type, including the one being
///    defined here. In this case the struct is `DuplicateTag`, so the enum must
///    contain the variant `DuplicateTag(DuplicateTag)`. This attribute is
///    required.
///
/// ```text
/// #[error(code = "E021", title = "duplicate tag `{tag}`")]
/// ```
///
/// 3. The `error` attribute indicates that this is an error with code "E021"
///    and title "duplicate tag `{tag}`". Notice the use of format arguments
///    in the title for specifying the tag. For each format argument there must
///    be a field in the structure with that name. The value of that field is
///    used when rendering the title. When defining a warning you use
///    `#[warning(...)]` instead of `#[error(...)]`, but one of the two
///    attributes must be present.
///
/// ```text
/// #[label("duplicate tag", loc, Level::Error)]
/// ```
///
/// 4. Then comes one or more `label` attributes, where each label is composed
///    of a text, the name of some field of type `SourceRef` in the structure,
///    and optionally, the label's error level. Valid error levels are:
///
///     - `Level::Error`
///     - `Level::Warning`
///     - `Level::Info`
///     - `Level::Note`
///     - `Level::Help`
///
///    If the level is omitted it will be either `Level::Error` or
///    `Level::Warning`, depending on whether we are defining an error with
///    `#[error(...)]`, or a warning with `#[warning(...)]`.
///
/// ```text
/// pub struct DuplicateTag {
///    report: Report,
///    tag: String,
///    loc: SourceRef,
/// }
/// ```
///
/// 4. Finally, we have the struct. The first field in the structure must be
///    `report: Report`. The rest of the fields vary from error to error
///
///
/// This is how the error looks when printed:
///
/// ```text
/// error[E021]: duplicate tag `tag1`
/// --> test.yar:1:18
///   |
/// 1 | rule test : tag1 tag1 { condition: true }
///   |                  ^^^^ duplicate tag
///   |
/// ```
///
#[proc_macro_derive(
    ErrorStruct,
    attributes(error, warning, label, footer, associated_enum)
)]
pub fn error_struct_macro_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    error::impl_error_struct_macro(input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// The `ErrorEnum` macro is used with enums that define YARA errors and
/// warnings.
///
/// This macro is used in combination with `ErrorStruct`, see the documentation
/// of `ErrorStruct` for details.
#[proc_macro_derive(ErrorEnum)]
pub fn error_enum_macro_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    error::impl_error_enum_macro(input)
        .unwrap_or_else(Error::into_compile_error)
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
        .unwrap_or_else(Error::into_compile_error)
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
    let args = match NestedMeta::parse_meta_list(args.into()) {
        Ok(args) => args,
        Err(e) => return darling::Error::from(e).write_errors().into(),
    };
    wasm_export::impl_wasm_export_macro(
        args,
        parse_macro_input!(input as ItemFn),
    )
    .unwrap_or_else(Error::into_compile_error)
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
    let args = match NestedMeta::parse_meta_list(args.into()) {
        Ok(args) => args,
        Err(e) => return darling::Error::from(e).write_errors().into(),
    };
    module_export::impl_module_export_macro(
        args,
        parse_macro_input!(input as ItemFn),
    )
    .unwrap_or_else(Error::into_compile_error)
    .into()
}
