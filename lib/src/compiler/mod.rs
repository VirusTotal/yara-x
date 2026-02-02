/*! Compiles YARA source code into binary form.

YARA rules must be compiled before they can be used for scanning data. This
module implements the YARA compiler.
*/

use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
#[cfg(feature = "logging")]
use std::time::Instant;
use std::{env, fmt, fs, io, iter};

use bitflags::bitflags;
use bstr::{BStr, ByteSlice};
use itertools::{izip, Itertools, MinMaxResult};
#[cfg(feature = "logging")]
use log::*;
use regex_syntax::hir;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use walrus::FunctionId;

use yara_x_parser::ast;
use yara_x_parser::ast::{Ident, Import, Include, RuleFlags, WithSpan, AST};
use yara_x_parser::cst::CSTStream;
use yara_x_parser::{Parser, Span};

use crate::compiler::base64::base64_patterns;
use crate::compiler::emit::{emit_rule_condition, EmitContext};
use crate::compiler::errors::{
    CompileError, ConflictingRuleIdentifier, CustomError, DuplicateRule,
    DuplicateTag, EmitWasmError, InvalidRegexp, InvalidUTF8, UnknownModule,
    UnusedPattern,
};
use crate::compiler::report::ReportBuilder;
use crate::compiler::{CompileContext, VarStack};
use crate::modules::BUILTIN_MODULES;
use crate::re::hir::{ChainedPattern, ChainedPatternGap};
use crate::string_pool::{BStringPool, StringPool};
use crate::symbols::{StackedSymbolTable, Symbol, SymbolLookup, SymbolTable};
use crate::types::{Func, Struct, TypeValue};
use crate::utils::cast;
use crate::variables::{is_valid_identifier, Variable, VariableError};
use crate::wasm::builder::WasmModuleBuilder;
use crate::wasm::{wasm_exports, WasmSymbols};
use crate::{re, wasm};

pub(crate) use crate::compiler::atoms::*;
pub(crate) use crate::compiler::context::*;
pub(crate) use crate::compiler::ir::*;

use crate::compiler::wsh::WarningSuppressionHook;
use crate::errors::{
    CircularIncludes, IncludeError, IncludeNotAllowed, IncludeNotFound,
    InvalidWarningCode,
};
use crate::linters::LinterResult;
use crate::models::PatternKind;

#[doc(inline)]
pub use crate::compiler::report::Patch;
#[doc(inline)]
pub use crate::compiler::rules::*;
#[doc(inline)]
pub use crate::compiler::warnings::*;

mod atoms;
mod context;
mod emit;
mod ir;
mod report;
mod rules;

#[cfg(test)]
mod tests;

pub mod base64;
pub mod errors;
pub mod linters;
pub mod warnings;
pub mod wsh;

/// A structure that describes some YARA source code.
///
/// This structure contains a `&str` pointing to the code itself, and an
/// optional `origin` that tells where the source code came from. The
/// most common use for `origin` is indicating the path of the file from
/// where the source code was obtained, but it can contain any arbitrary
/// string. This string, if provided, will appear in error messages. For
/// example, in this error message `origin` was set to `some_file.yar`:
///
/// ```text
/// error: syntax error
///  --> some_file.yar:4:17
///   |
/// 4 | ... more details
/// ```
///
/// # Example
///
/// ```
/// use yara_x::SourceCode;
/// let src = SourceCode::from("rule test { condition: true }").with_origin("some_file.yar");
/// ```
///
#[derive(Debug, Clone)]
pub struct SourceCode<'src> {
    /// A reference to the source code itself. This is a BStr because the
    /// source code could contain non-UTF8 content.
    pub(crate) raw: &'src BStr,
    /// A reference to the source code after validating that it is valid
    /// UTF-8.
    pub(crate) valid: Option<&'src str>,
    /// An optional string that tells which is the origin of the code. Usually
    /// a file path.
    pub(crate) origin: Option<String>,
}

impl<'src> SourceCode<'src> {
    /// Sets a string that describes the origin of the source code.
    ///
    /// This is usually the path of the file that contained the source code,
    /// but it can be an arbitrary string. The origin appears in error and
    /// warning messages.
    pub fn with_origin<S: Into<String>>(self, origin: S) -> Self {
        Self { raw: self.raw, valid: self.valid, origin: Some(origin.into()) }
    }

    /// Returns the source code as a `&str`.
    ///
    /// If the source code is not valid UTF-8 it will return an error.
    fn as_str(&mut self) -> Result<&'src str, bstr::Utf8Error> {
        match self.valid {
            // We already know that source code is valid UTF-8, return it
            // as is.
            Some(s) => Ok(s),
            // We don't know yet if the source code is valid UTF-8, some
            // validation must be done. If validation fails an error is
            // returned.
            None => {
                let src = self.raw.to_str()?;
                self.valid = Some(src);
                Ok(src)
            }
        }
    }
}

impl<'src> From<&'src str> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&str`.
    fn from(src: &'src str) -> Self {
        // The input is a &str, therefore it's guaranteed to be valid UTF-8
        // and the `valid` field can be initialized.
        Self { raw: BStr::new(src), valid: Some(src), origin: None }
    }
}

impl<'src> From<&'src [u8]> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&[u8]`.
    ///
    /// As `src` is not guaranteed to be a valid UTF-8 string, the parser will
    /// verify it and return an error if invalid UTF-8 characters are found.
    fn from(src: &'src [u8]) -> Self {
        // The input is a &[u8], its content is not guaranteed to be valid
        // UTF-8 so the `valid` field is set to `None`. The `validate_utf8`
        // function will be called for validating the source code before
        // being parsed.
        Self { raw: BStr::new(src), valid: None, origin: None }
    }
}

/// Compiles a YARA source code.
///
/// This function receives any type that implements the `Into<SourceCode>` trait,
/// which includes `&str`, `String` and [`SourceCode`] and produces compiled
/// [`Rules`] that can be passed later to the scanner.
///
/// # Example
///
/// ```rust
/// # use yara_x;
/// let rules = yara_x::compile("rule test { condition: true }").unwrap();
/// let mut scanner = yara_x::Scanner::new(&rules);
/// let results = scanner.scan("Lorem ipsum".as_bytes()).unwrap();
/// assert_eq!(results.matching_rules().len(), 1);
/// ```
pub fn compile<'src, S>(src: S) -> Result<Rules, CompileError>
where
    S: Into<SourceCode<'src>>,
{
    let mut compiler = Compiler::new();
    compiler.add_source(src)?;
    Ok(compiler.build())
}

/// Structure that contains information about a rule namespace.
///
/// Includes NamespaceId, the IdentId corresponding to the namespace's
/// identifier, and the symbol table that contains the symbols defined
/// in the namespace.
struct Namespace {
    id: NamespaceId,
    ident_id: IdentId,
    symbols: Rc<RefCell<SymbolTable>>,
}

/// Compiles YARA source code producing a set of compiled [`Rules`].
///
/// The two most important methods in this type are [`Compiler::add_source`]
/// and [`Compiler::build`]. The former tells the compiler which YARA source
/// code must be compiled, and can be called multiple times with different
/// set of rules. The latter consumes the compiler and produces a set of
/// compiled [`Rules`].
///
/// # Example
///
/// ```rust
/// # use yara_x;
/// let mut compiler = yara_x::Compiler::new();
///
/// compiler
///     .add_source(r#"
///         rule always_true {
///             condition: true
///         }"#)?
///     .add_source(r#"
///         rule always_false {
///             condition: false
///         }"#)?;///
///
/// let rules = compiler.build();
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
pub struct Compiler<'a> {
    /// Mimics YARA behaviour with respect to regular expressions, allowing
    /// some constructs that are invalid in YARA-X by default, like invalid
    /// escape sequences.
    relaxed_re_syntax: bool,

    /// If true, the compiler hoists loop-invariant expressions (i.e: those
    /// that don't vary on each iteration of the loop), moving them outside
    /// the loop.
    hoisting: bool,

    /// List of directories where the compiler should look for included files.
    /// If `None`, the current directory is used.
    include_dirs: Option<Vec<PathBuf>>,

    /// If true, slow patterns produce an error instead of a warning. A slow
    /// pattern is one with atoms shorter than 2 bytes.
    error_on_slow_pattern: bool,

    /// If true, a slow loop produces an error instead of a warning. A slow
    /// rule is one where the upper bound of the loop is potentially large.
    /// Like for example: `for all x in (0..filesize) : (...)`
    error_on_slow_loop: bool,

    /// If true, include statements are allowed. If false, include statements
    /// will produce a compile error.
    includes_enabled: bool,

    /// Tracks the paths of the files that have been included by nested
    /// includes. This is useful for detecting circular includes and resolving
    /// relative includes.
    include_stack: Vec<PathBuf>,

    /// Used for generating error and warning reports.
    report_builder: ReportBuilder,

    /// The main symbol table used by the compiler. This is actually a stack of
    /// symbol tables where the bottom-most table is the one that contains
    /// global identifiers like built-in functions and user-defined global
    /// identifiers.
    symbol_table: StackedSymbolTable,

    /// Symbol table that contains the global identifiers, including built-in
    /// functions like `uint8`, `uint16`, etc. This symbol table is at the
    /// bottom of the `symbol_table`'s stack. This field is used when we
    /// need to access the global symbol table directly, for example for
    /// defining new global variables.
    global_symbols: Rc<RefCell<SymbolTable>>,

    /// Information about the current namespace (i.e: the namespace that will
    /// contain any new rules added via a call to `add_sources`.
    current_namespace: Namespace,

    /// Pool that contains all the identifiers used in the rules. Each
    /// identifier appears only once, even if they are used by multiple
    /// rules. For example, the pool contains a single copy of the common
    /// identifier `$a`. Each identifier have a unique 32-bits [`IdentId`]
    /// that can be used for retrieving the identifier from the pool.
    ident_pool: StringPool<IdentId>,

    /// Similar to `ident_pool` but for regular expressions found in rule
    /// conditions.
    regexp_pool: StringPool<RegexpId>,

    /// Similar to `ident_pool` but for string literals found in the source
    /// code. As literal strings in YARA can contain arbitrary bytes, a pool
    /// capable of storing [`bstr::BString`] must be used, the [`String`] type
    /// only accepts valid UTF-8. This pool also stores the atoms extracted
    /// from patterns.
    lit_pool: BStringPool<LiteralId>,

    /// Intermediate representation (IR) tree for condition of the rule that
    /// is currently being compiled. After compiling each rule the tree is
    /// cleared, but it will be reused for the next rule.
    ir: IR,

    /// Builder for creating the WebAssembly module that contains the code
    /// for all rule conditions.
    wasm_mod: WasmModuleBuilder,

    /// Struct that contains the IDs for WASM memories, global and local
    /// variables, etc.
    wasm_symbols: WasmSymbols,

    /// Map that contains the functions that are callable from WASM code. These
    /// are the same functions in [`static@WASM_EXPORTS`]. This map allows to
    /// retrieve the WASM [`FunctionId`] from the fully qualified mangled
    /// function name (e.g: `my_module.my_struct.my_func@ii@i`)
    wasm_exports: FxHashMap<String, FunctionId>,

    /// Map that associates a `PatternId` to a certain filesize bound.
    ///
    /// A condition like `filesize < 1000 and $a` only matches if `filesize`
    /// is less than 1000. Therefore, the pattern `$a` does not need be
    /// checked for files of size 1000 bytes or larger.
    ///
    /// In this case, the map will contain an entry associating `$a` to a
    /// `FilesizeBounds` value like:
    /// `FilesizeBounds{start: Bound::Unbounded, end: Bound:Excluded(1000)}`.
    filesize_bounds: FxHashMap<PatternId, FilesizeBounds>,

    /// A vector with all the rules that has been compiled. A [`RuleId`] is
    /// an index in this vector.
    rules: Vec<RuleInfo>,

    /// Next (not used yet) [`PatternId`].
    next_pattern_id: PatternId,

    /// Map used for de-duplicating pattern. Keys are the pattern's IR and
    /// values are the `PatternId` assigned to each pattern. Every time a rule
    /// declares a pattern, this map is used for determining if the same
    /// pattern (i.e: a pattern with exactly the same IR) was already declared
    /// by some other rule. If that's the case, that same pattern is re-used.
    patterns: FxHashMap<Pattern, PatternId>,

    /// A vector with all the sub-patterns from all the rules. A
    /// [`SubPatternId`] is an index in this vector.
    sub_patterns: Vec<(PatternId, SubPattern)>,

    /// Vector that contains the [`SubPatternId`] for sub-patterns that can
    /// match only at a fixed offset within the scanned data. These sub-patterns
    /// are not added to the Aho-Corasick automaton.
    anchored_sub_patterns: Vec<SubPatternId>,

    /// A vector that contains all the atoms generated from the patterns.
    /// Each atom has an associated [`SubPatternId`] that indicates the
    /// sub-pattern it belongs to.
    atoms: Vec<SubPatternAtom>,

    /// A vector that contains the code for all regexp patterns (this includes
    /// hex patterns which are just a special case of regexp). The code for
    /// each regexp is appended to the vector, during the compilation process
    /// and the atoms extracted from the regexp contain offsets within this
    /// vector. This vector contains both forward and backward code.
    re_code: Vec<u8>,

    /// Vector with the names of all the imported modules. The vector contains
    /// the [`IdentId`] corresponding to the module's identifier.
    imported_modules: Vec<IdentId>,

    /// Names of modules that are known, but not supported. When an `import`
    /// statement with one of these modules is found, the statement is accepted
    /// without causing an error, but a warning is raised to let the user know
    /// that the module is not supported. Any rule that depends on an unsupported
    /// module is ignored.
    ignored_modules: FxHashSet<String>,

    /// Keys in this map are the modules that are banned, and values are a pair
    /// of strings with the title and message for the error that will be shown
    /// if the banned module is imported.
    banned_modules: FxHashMap<String, (String, String)>,

    /// Keys in this map are the name of rules that will be ignored because they
    /// depend on unsupported modules, either directly or indirectly. Values are
    /// the names of the unsupported modules they depend on.
    ignored_rules: FxHashMap<String, String>,

    /// Structure where each field corresponds to a global identifier or a module
    /// imported by the rules. For fields corresponding to modules, the value is
    /// the structure that describes the module.
    root_struct: Struct,

    /// Warnings generated while compiling the rules.
    warnings: Warnings,

    /// Errors generated while compiling the rules.
    errors: Vec<CompileError>,

    /// Features enabled for this compiler. See [`Compiler::enable_feature`]
    /// for details.
    features: FxHashSet<String>,

    /// Optional writer where the compiler writes the IR produced by each rule.
    /// This is used for test cases and debugging.
    ir_writer: Option<Box<dyn Write>>,

    /// Linters applied to each rule during compilation. The linters are added
    /// to the compiler using [`Compiler::add_linter`]:
    linters: Vec<Box<dyn linters::Linter + 'a>>,
}

impl<'a> Compiler<'a> {
    /// Creates a new YARA compiler.
    pub fn new() -> Self {
        let mut ident_pool = StringPool::new();
        let mut symbol_table = StackedSymbolTable::new();

        let global_symbols = symbol_table.push_new();

        // Add symbols for built-in functions like uint8, uint16, etc.
        for export in wasm_exports()
            // Get only the public exports not belonging to a YARA module.
            .filter(|e| e.public && e.builtin())
        {
            let func = Rc::new(Func::from(export.mangled_name));
            let symbol = Symbol::Func(func);

            global_symbols.borrow_mut().insert(export.name, symbol);
        }

        // Create the default namespace. Rule identifiers will be added to this
        // namespace, unless the user defines some namespace explicitly by calling
        // `Compiler::new_namespace`.
        let default_namespace = Namespace {
            id: NamespaceId(0),
            ident_id: ident_pool.get_or_intern("default"),
            symbols: symbol_table.push_new(),
        };

        // At this point the symbol table (which is a stacked symbol table) has
        // two layers, the global symbols at the bottom, and the default
        // namespace on top of it. Calls to `Compiler::new_namespace` replace
        // the top layer (default namespace) with a new one, but the bottom
        // layer remains, so the global symbols are shared by all namespaces.

        // Create a WASM module builder. This object is used for building the
        // WASM module that will execute the rule conditions.
        let mut wasm_mod = WasmModuleBuilder::new();

        wasm_mod.namespaces_per_func(20);
        wasm_mod.rules_per_func(10);

        let wasm_symbols = wasm_mod.wasm_symbols();
        let wasm_exports = wasm_mod.wasm_exports();

        let mut ir = IR::new();

        if cfg!(feature = "constant-folding") {
            ir.constant_folding(true);
        }

        Self {
            ir,
            ident_pool,
            global_symbols,
            symbol_table,
            wasm_mod,
            wasm_symbols,
            wasm_exports,
            relaxed_re_syntax: false,
            hoisting: false,
            error_on_slow_pattern: false,
            error_on_slow_loop: false,
            next_pattern_id: PatternId(0),
            current_namespace: default_namespace,
            features: FxHashSet::default(),
            warnings: Warnings::default(),
            errors: Vec::new(),
            rules: Vec::new(),
            sub_patterns: Vec::new(),
            anchored_sub_patterns: Vec::new(),
            atoms: Vec::new(),
            re_code: Vec::new(),
            imported_modules: Vec::new(),
            ignored_modules: FxHashSet::default(),
            banned_modules: FxHashMap::default(),
            ignored_rules: FxHashMap::default(),
            filesize_bounds: FxHashMap::default(),
            root_struct: Struct::new().make_root(),
            report_builder: ReportBuilder::new(),
            lit_pool: BStringPool::new(),
            regexp_pool: StringPool::new(),
            patterns: FxHashMap::default(),
            ir_writer: None,
            linters: Vec::new(),
            include_dirs: None,
            includes_enabled: true,
            include_stack: Vec::new(),
        }
    }

    /// Adds a directory to the list of directories where the compiler should
    /// look for included files.
    ///
    /// When an `include` statement is found, the compiler looks for the included
    /// file in the directories added with this function, in the order they were
    /// added.
    ///
    /// If this function is not called, the compiler will only look for included
    /// files in the current directory.
    ///
    /// Use [Compiler::enable_includes] for controlling whether include statements
    /// are allowed or not.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use yara_x::Compiler;
    /// # use std::path::Path;
    /// let mut compiler = Compiler::new();
    /// compiler.add_include_dir("/path/to/rules")
    ///         .add_include_dir("/another/path");
    /// ```
    pub fn add_include_dir<P: AsRef<std::path::Path>>(
        &mut self,
        dir: P,
    ) -> &mut Self {
        self.include_dirs
            .get_or_insert_default()
            .push(dir.as_ref().to_path_buf());
        self
    }

    /// Adds some YARA source code to be compiled.
    ///
    /// The `src` parameter accepts any type that implements [`Into<SourceCode>`],
    /// such as `&str`, `&[u8]`, or an instance of [`SourceCode`] itself. The source
    /// code may include one or more YARA rules.
    ///
    /// You can call this function multiple times to add different sets of rules.
    /// If the provided source code contains syntax or semantic errors that prevent
    /// compilation, the function returns the first encountered error. All errors
    /// found during compilation are also recorded and can be retrieved using
    /// [`Compiler::errors`].
    ///
    /// Even if previous calls to this function resulted in compilation errors,
    /// you may continue adding additional rules. Only successfully compiled rules
    /// will be included in the final rule set.
    pub fn add_source<'src, S>(
        &mut self,
        src: S,
    ) -> Result<&mut Self, CompileError>
    where
        S: Into<SourceCode<'src>>,
    {
        // Convert `src` into an instance of `SourceCode` if it is something
        // else, like a &str.
        let mut src = src.into();

        // Register source code, even before validating that it is UTF-8. In
        // case of UTF-8 encoding errors we want to report that error too,
        // and we need the source code registered for creating the report.
        self.report_builder.register_source(&src);

        // Make sure that the source code is valid UTF-8, or return an error
        // if otherwise.
        let ast = match src.as_str() {
            Ok(src) => {
                // Parse the source code and build the Abstract Syntax Tree.
                let cst = Parser::new(src.as_bytes());
                let cst =
                    WarningSuppressionHook::from(cst).hook(|warning, span| {
                        self.warnings.suppress(warning, span);
                    });

                AST::from(CSTStream::new(src.as_bytes(), cst))
            }
            Err(err) => {
                let span_start = err.valid_up_to();
                let span_end = if let Some(error_len) = err.error_len() {
                    // `error_len` is the number of invalid UTF-8 bytes found
                    // after `span_start`. Round the number up to the next 3
                    // bytes boundary because invalid bytes are replaced with
                    // the Unicode replacement characters that takes 3 bytes.
                    // This way the span ends at a valid UTF-8 character
                    // boundary.
                    span_start + error_len.next_multiple_of(3)
                } else {
                    span_start
                };

                let err = InvalidUTF8::build(
                    &self.report_builder,
                    self.report_builder.span_to_code_loc(Span(
                        span_start as u32..span_end as u32,
                    )),
                );

                self.errors.push(err.clone());
                return Err(err);
            }
        };

        // Store the current length of the `errors` vector, so that we can
        // know if more errors were added.
        let existing_errors = self.errors.len();

        self.c_items(ast.items());

        self.warnings.clear_suppressed();

        self.errors.extend(
            ast.into_errors()
                .into_iter()
                .map(|err| CompileError::from(&self.report_builder, err)),
        );

        // More errors were added? Return the first error that was added.
        if self.errors.len() > existing_errors {
            return Err(self.errors[existing_errors].clone());
        }

        Ok(self)
    }

    /// Defines a global variable and sets its initial value.
    ///
    /// Global variables must be defined before adding any YARA source code
    /// that references them via [`Compiler::add_source`]. Once defined, the
    /// variable's initial value is preserved in the compiled [`Rules`] and
    /// will be used unless overridden.
    ///
    /// When scanning, each scanner instance can modify the initial value of
    /// the variable using [`crate::Scanner::set_global`].
    ///
    /// `T` can be any type that implements [`TryInto<Variable>`], including:
    /// `i64`, `i32`, `i16`, `i8`, `u32`, `u16`, `u8`, `f64`, `f32`, `bool`,
    /// `&str`, `String` and [`serde_json::Value`].
    ///
    /// ```
    /// # use yara_x::Compiler;
    /// assert!(Compiler::new()
    ///     .define_global("some_int", 1)?
    ///     .add_source("rule some_int_not_zero {condition: some_int != 0}")
    ///     .is_ok());
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn define_global<T: TryInto<Variable>>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<&mut Self, VariableError>
    where
        VariableError: From<<T as TryInto<Variable>>::Error>,
    {
        if !is_valid_identifier(ident) {
            return Err(VariableError::InvalidIdentifier(ident.to_string()));
        }

        let var: Variable = value.try_into()?;
        let type_value: TypeValue = var.into();

        if self.root_struct.add_field(ident, type_value).is_some() {
            return Err(VariableError::AlreadyExists(ident.to_string()));
        }

        self.global_symbols
            .borrow_mut()
            .insert(ident, self.root_struct.lookup(ident).unwrap());

        Ok(self)
    }

    /// Creates a new namespace.
    ///
    /// Further calls to [`Compiler::add_source`] will put the rules under the
    /// newly created namespace. If the new namespace is named as the current
    /// one, no new namespace is created.
    ///
    /// In the example below both rules `foo` and `bar` are put into the same
    /// namespace (the default namespace), therefore `bar` can use `foo` as
    /// part of its condition, and everything is ok.
    ///
    /// ```
    /// # use yara_x::Compiler;
    /// assert!(Compiler::new()
    ///     .add_source("rule foo {condition: true}")?
    ///     .add_source("rule bar {condition: foo}")
    ///     .is_ok());
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// In this other example the rule `foo` is put in the default namespace,
    /// but the rule `bar` is put under the `bar` namespace. This implies that
    /// `foo` is not visible to `bar`, and the second call to `add_source`
    /// fails.
    ///
    /// ```
    /// # use yara_x::Compiler;
    /// assert!(Compiler::new()
    ///     .add_source("rule foo {condition: true}")?
    ///     .new_namespace("bar")
    ///     .add_source("rule bar {condition: foo}")
    ///     .is_err());
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new_namespace(&mut self, namespace: &str) -> &mut Self {
        let current_namespace = self
            .ident_pool
            .get(self.current_namespace.ident_id)
            .expect("expecting a namespace");
        // If the current namespace is already named as the new namespace
        // this function has no effect.
        if namespace == current_namespace {
            return self;
        }
        // Remove the symbol table corresponding to the current namespace.
        self.symbol_table.pop().expect("expecting a namespace");
        // Create a new namespace. The NamespaceId is simply the ID of the
        // previous namespace + 1.
        self.current_namespace = Namespace {
            id: NamespaceId(self.current_namespace.id.0 + 1),
            ident_id: self.ident_pool.get_or_intern(namespace),
            symbols: self.symbol_table.push_new(),
        };
        self.ignored_rules.clear();
        self.wasm_mod.new_namespace();
        self
    }

    /// Builds the source code previously added to the compiler.
    ///
    /// This function consumes the compiler and returns an instance of
    /// [`Rules`].
    pub fn build(self) -> Rules {
        // Finish building the WASM module.
        let wasm_mod = self.wasm_mod.build().emit_wasm();

        #[cfg(feature = "logging")]
        let start = Instant::now();

        // Compile the WASM module for the current platform. This panics
        // if the WASM code is invalid, which should not happen as the code is
        // emitted by YARA itself. If this ever happens is probably because
        // wrong WASM code is being emitted.
        let compiled_wasm_mod = wasmtime::Module::from_binary(
            wasm::get_engine(),
            wasm_mod.as_slice(),
        )
        .expect("WASM module is not valid");

        #[cfg(feature = "logging")]
        info!("WASM module build time: {:?}", Instant::elapsed(&start));

        // The structure that contains the global variables is serialized before
        // being passed to the `Rules` struct. This is because we want `Rules`
        // to be `Send`, so that it can be shared with scanners running in
        // different threads. In order for `Rules` to be `Send`, it can't
        // contain fields that are not `Send`. As `Struct` is not `Send` we
        // can't have a `Struct` field in `Rules`, so what we have a `Vec<u8>`
        // with a serialized version of the struct.
        //
        // An alternative is changing the `Rc` in some variants of `TypeValue`
        // to `Arc`, as the root cause that prevents `Struct` from being `Send`
        // is the use of `Rc` in `TypeValue`.
        let serialized_globals = bincode::serde::encode_to_vec(
            &self.root_struct,
            bincode::config::standard().with_variable_int_encoding(),
        )
        .expect("failed to serialize global variables");

        let mut rules = Rules {
            serialized_globals,
            wasm_mod,
            compiled_wasm_mod: Some(compiled_wasm_mod),
            relaxed_re_syntax: self.relaxed_re_syntax,
            ac: None,
            num_patterns: self.next_pattern_id.0 as usize,
            ident_pool: self.ident_pool,
            regexp_pool: self.regexp_pool,
            lit_pool: self.lit_pool,
            imported_modules: self.imported_modules,
            rules: self.rules,
            sub_patterns: self.sub_patterns,
            anchored_sub_patterns: self.anchored_sub_patterns,
            atoms: self.atoms,
            re_code: self.re_code,
            warnings: self.warnings.into(),
            filesize_bounds: self.filesize_bounds,
        };

        rules.build_ac_automaton();
        rules
    }

    /// Adds a linter to the compiler.
    ///
    /// Linters perform additional checks to each YARA rule, generating
    /// warnings when a rule does not meet the linter's requirements. See
    /// [`crate::linters`] for a list of available linters.
    pub fn add_linter<L: linters::Linter + 'a>(
        &mut self,
        linter: L,
    ) -> &mut Self {
        self.linters.push(Box::new(linter));
        self
    }

    /// Enables a feature on this compiler.
    ///
    /// When defining the structure of a module in a `.proto` file, you can
    /// specify that certain fields are accessible only when one or more
    /// features are enabled. For example, the snippet below shows the
    /// definition of a field named `requires_foo_and_bar`, which can be
    /// accessed only when both features "foo" and "bar" are enabled.
    ///
    /// ```protobuf
    /// optional uint64 requires_foo_and_bar = 500 [
    ///   (yara.field_options) = {
    ///     acl: [
    ///       {
    ///         allow_if: "foo",
    ///         error_title: "foo is required",
    ///         error_label: "this field was used without foo"
    ///       },
    ///       {
    ///         allow_if: "bar",
    ///         error_title: "bar is required",
    ///         error_label: "this field was used without bar"
    ///       }
    ///     ]
    ///   }
    /// ];
    /// ```
    ///
    /// If some of the required features are not enabled, using this field in
    /// a YARA rule will cause an error while compiling the rules. The error
    /// looks like:
    ///
    /// ```text
    /// error[E034]: foo is required
    ///  --> line:5:29
    ///   |
    /// 5 |  test_proto2.requires_foo_and_bar == 0
    ///   |              ^^^^^^^^^^^^^^^^^^^^ this field was used without foo
    ///   |
    /// ```
    ///
    /// Notice that both the title and label in the error message are defined
    /// in the .proto file.
    ///
    /// # Important
    ///
    /// This API is hidden from the public documentation because it is unstable
    /// and subject to change.
    #[doc(hidden)]
    pub fn enable_feature<F: Into<String>>(
        &mut self,
        feature: F,
    ) -> &mut Self {
        self.features.insert(feature.into());
        self
    }

    /// Tell the compiler that a YARA module is not supported.
    ///
    /// Import statements for ignored modules will be ignored without errors,
    /// but a warning will be issued. Any rule that makes use of an ignored
    /// module will be also ignored, while the rest of the rules that don't
    /// rely on that module will be correctly compiled.
    pub fn ignore_module<M: Into<String>>(&mut self, module: M) -> &mut Self {
        self.ignored_modules.insert(module.into());
        self
    }

    /// Tell the compiler that a YARA module can't be used.
    ///
    /// Import statements for the banned module will cause an error. The error
    /// message can be customized by using the given error title and message.
    ///
    /// If this function is called multiple times with the same module name,
    /// the error title and message will be updated.
    pub fn ban_module<M: Into<String>, T: Into<String>, E: Into<String>>(
        &mut self,
        module: M,
        error_title: T,
        error_message: E,
    ) -> &mut Self {
        self.banned_modules
            .insert(module.into(), (error_title.into(), error_message.into()));
        self
    }

    /// Specifies whether the compiler should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles.
    ///
    /// The default setting is `false`.
    pub fn colorize_errors(&mut self, yes: bool) -> &mut Self {
        self.report_builder.with_colors(yes);
        self
    }

    /// Sets the maximum number of columns in error messages.
    ///
    /// The default value is 140.
    pub fn errors_max_width(&mut self, width: usize) -> &mut Self {
        self.report_builder.max_width(width);
        self
    }

    /// Enables or disables a specific type of warning.
    ///
    /// Each warning type has a description code (i.e: `slow_pattern`,
    /// `unsupported_module`, etc.). This function allows to enable or disable
    /// a specific type of warning identified by the given code.
    ///
    /// Returns an error if the given warning code doesn't exist.
    pub fn switch_warning(
        &mut self,
        code: &str,
        enabled: bool,
    ) -> Result<&mut Self, InvalidWarningCode> {
        self.warnings.switch_warning(code, enabled)?;
        Ok(self)
    }

    /// Enables or disables all warnings.
    pub fn switch_all_warnings(&mut self, enabled: bool) -> &mut Self {
        self.warnings.switch_all_warnings(enabled);
        self
    }

    /// Enables a more relaxed syntax check for regular expressions.
    ///
    /// YARA-X enforces stricter regular expression syntax compared to YARA.
    /// For instance, YARA accepts invalid escape sequences and treats them
    /// as literal characters (e.g., \R is interpreted as a literal 'R'). It
    /// also allows some special characters to appear unescaped, inferring
    /// their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
    /// literal, but in `/foo{0,1}bar/` they form the repetition operator
    /// `{0,1}`).
    ///
    /// This setting controls whether the compiler should mimic YARA's behavior,
    /// allowing constructs that YARA-X doesn't accept by default.
    ///
    /// This should be called before any rule is added to the compiler.
    ///
    /// # Panics
    ///
    /// If called after adding rules to the compiler.
    pub fn relaxed_re_syntax(&mut self, yes: bool) -> &mut Self {
        if !self.rules.is_empty() {
            panic!("calling relaxed_re_syntax in non-empty compiler")
        }
        self.relaxed_re_syntax = yes;
        self
    }

    /// When enabled, slow patterns produce an error instead of a warning.
    ///
    /// This is disabled by default.
    pub fn error_on_slow_pattern(&mut self, yes: bool) -> &mut Self {
        self.error_on_slow_pattern = yes;
        self
    }

    /// When enabled, potentially slow loops produce an error instead of a
    /// warning.
    ///
    /// This is disabled by default.
    pub fn error_on_slow_loop(&mut self, yes: bool) -> &mut Self {
        self.error_on_slow_loop = yes;
        self
    }

    /// Controls whether `include` statements are allowed.
    ///
    /// By default, the compiler allows the use of `include` statements, which
    /// include the content of other files. When includes are disabled, any
    /// attempt to use an `include` statement will result in a compile error.
    ///
    /// ```
    /// # use yara_x::Compiler;
    /// let mut compiler = Compiler::new();
    /// compiler.enable_includes(false);  // Disable includes
    /// ```
    pub fn enable_includes(&mut self, yes: bool) -> &mut Self {
        self.includes_enabled = yes;
        self
    }

    /// When enabled, the compiler tries to optimize rule conditions.
    ///
    /// The optimizations usually reduce condition evaluation times, specially
    /// in complex rules that contain loops, but it can break short-circuit
    /// evaluation rules because some subexpressions are not executed in the
    /// order they appear in the source code.
    ///
    /// This is a very experimental feature.
    #[doc(hidden)]
    pub fn condition_optimization(&mut self, yes: bool) -> &mut Self {
        self.hoisting(yes)
    }

    pub(crate) fn hoisting(&mut self, yes: bool) -> &mut Self {
        self.hoisting = yes;
        self
    }

    /// Retrieves all errors generated by the compiler.
    ///
    /// This method returns every error encountered during the compilation,
    /// across all invocations of [`Compiler::add_source`].
    #[inline]
    pub fn errors(&self) -> &[CompileError] {
        self.errors.as_slice()
    }

    /// Returns the warnings emitted by the compiler.
    ///
    /// This method returns every warning issued during the compilation,
    /// across all invocations of [`Compiler::add_source`].
    #[inline]
    pub fn warnings(&self) -> &[Warning] {
        self.warnings.as_slice()
    }

    /// Emits a `.wasm` file with the WASM module generated by the compiler.
    ///
    /// This file can be inspected and converted to WASM text format by using
    /// third-party [tooling](https://github.com/WebAssembly/wabt). This is
    /// useful for debugging issues with incorrectly emitted WASM code.
    pub fn emit_wasm_file<P>(self, path: P) -> Result<(), EmitWasmError>
    where
        P: AsRef<Path>,
    {
        let mut wasm_mod = self.wasm_mod.build();
        Ok(wasm_mod.emit_wasm_file(path)?)
    }

    /// Sets a writer where the compiler will write the Intermediate
    /// Representation (IR) of compiled conditions.
    ///
    /// This is used for testing and debugging purposes.
    #[doc(hidden)]
    pub fn set_ir_writer<W: Write + 'static>(&mut self, w: W) -> &mut Self {
        self.ir_writer = Some(Box::new(w));
        self
    }
}

impl Compiler<'_> {
    fn add_sub_pattern<I, F, A>(
        &mut self,
        pattern_id: PatternId,
        sub_pattern: SubPattern,
        atoms: I,
        f: F,
    ) -> SubPatternId
    where
        I: Iterator<Item = A>,
        F: Fn(SubPatternId, A) -> SubPatternAtom,
    {
        let sub_pattern_id = SubPatternId(self.sub_patterns.len() as u32);

        // Sub-patterns that are anchored at some fixed offset are not added to
        // the Aho-Corasick automata. Instead, their IDs are added to the
        // anchored_sub_patterns list.
        if let SubPattern::Literal { anchored_at: Some(_), .. } = sub_pattern {
            self.anchored_sub_patterns.push(sub_pattern_id);
        } else {
            self.atoms.extend(atoms.map(|atom| f(sub_pattern_id, atom)));
        }

        self.sub_patterns.push((pattern_id, sub_pattern));

        sub_pattern_id
    }

    /// Checks if another rule, module or variable has the given identifier and
    /// return an error in that case.
    fn check_for_existing_identifier(
        &self,
        ident: &Ident,
    ) -> Result<(), CompileError> {
        if let Some(symbol) = self.symbol_table.lookup(ident.name) {
            return match symbol {
                // Found another rule with the same name.
                Symbol::Rule { rule_id, .. } => Err(DuplicateRule::build(
                    &self.report_builder,
                    ident.name.to_string(),
                    self.report_builder.span_to_code_loc(ident.span()),
                    self.rules
                        .get(rule_id.0 as usize)
                        .unwrap()
                        .ident_ref
                        .clone(),
                )),
                // Found another symbol that is not a rule, but has the same
                // name.
                _ => Err(ConflictingRuleIdentifier::build(
                    &self.report_builder,
                    ident.name.to_string(),
                    self.report_builder.span_to_code_loc(ident.span()),
                )),
            };
        }
        Ok(())
    }

    /// Checks that tags are not duplicate.
    fn check_for_duplicate_tags(
        &self,
        tags: &[Ident],
    ) -> Result<(), CompileError> {
        let mut s = HashSet::new();
        for tag in tags {
            if !s.insert(tag.name) {
                return Err(DuplicateTag::build(
                    &self.report_builder,
                    tag.name.to_string(),
                    self.report_builder.span_to_code_loc(tag.span()),
                ));
            }
        }
        Ok(())
    }

    /// Interns a literal in the literals pool.
    ///
    /// If `wide` is true the literal gets zeroes interleaved between each byte
    /// before being interned.
    fn intern_literal(&mut self, literal: &[u8], wide: bool) -> LiteralId {
        let wide_pattern;
        let literal_bytes = if wide {
            wide_pattern = make_wide(literal);
            wide_pattern.as_bytes()
        } else {
            literal
        };
        self.lit_pool.get_or_intern(literal_bytes)
    }

    /// Takes a snapshot of the compiler's state at this moment.
    ///
    /// The returned [`Snapshot`] can be passed to [`Compiler::restore_snapshot`]
    /// for restoring the compiler to the state it was when the snapshot was
    /// taken.
    ///
    /// This is useful when the compilation of a rule fails, for restoring the
    /// compiler to the state it had before starting compiling the failed rule,
    /// which avoids leaving junk in the compiler's internal structures.
    fn take_snapshot(&self) -> Snapshot {
        Snapshot {
            next_pattern_id: self.next_pattern_id,
            rules_len: self.rules.len(),
            atoms_len: self.atoms.len(),
            re_code_len: self.re_code.len(),
            sub_patterns_len: self.sub_patterns.len(),
            symbol_table_len: self.symbol_table.len(),
        }
    }

    /// Restores the compiler's to a previous state.
    ///
    /// Use [`Compiler::take_snapshot`] for taking a snapshot of the compiler's
    /// state.
    fn restore_snapshot(&mut self, snapshot: Snapshot) {
        self.next_pattern_id = snapshot.next_pattern_id;
        self.rules.truncate(snapshot.rules_len);
        self.sub_patterns.truncate(snapshot.sub_patterns_len);
        self.re_code.truncate(snapshot.re_code_len);
        self.atoms.truncate(snapshot.atoms_len);
        self.symbol_table.truncate(snapshot.symbol_table_len);

        // Pattern IDs that are >= next_pattern_id, are being discarded. Any pattern
        // or file size bound associated to such IDs must be removed.

        self.patterns
            .retain(|_, pattern_id| *pattern_id < snapshot.next_pattern_id);

        self.filesize_bounds
            .retain(|pattern_id, _| *pattern_id < snapshot.next_pattern_id);
    }

    /// Returns true if the bytes in the slice are all 0x00, 0x90, or 0xff.
    fn common_byte_repetition(bytes: &[u8]) -> bool {
        let mut all_x00 = true;
        let mut all_x90 = true;
        let mut all_xff = true;

        for b in bytes {
            match *b {
                0x00 => {
                    all_x90 = false;
                    all_xff = false;
                }
                0x90 => {
                    all_x00 = false;
                    all_xff = false;
                }
                0xff => {
                    all_x00 = false;
                    all_x90 = false;
                }
                _ => return false,
            }
            if !all_x00 && !all_x90 && !all_xff {
                return false;
            }
        }

        true
    }

    /// Reads the file specified by an `include` statement.
    ///
    /// Tries to read the file in the include directories that were specified
    /// with [`Compiler::add_include_dir`], or in the current directory, if
    /// no include directories were specified.
    ///
    /// The function returns both the content and the path of the included file
    /// relative to the current directory, or an error if the included file could
    /// not be read.
    fn read_included_file(
        &mut self,
        include: &Include,
    ) -> Result<(Vec<u8>, PathBuf), CompileError> {
        let read_file =
            |path: PathBuf| -> Result<(Vec<u8>, PathBuf), io::Error> {
                let mut path = path.canonicalize()?;
                let content = fs::read(&path)?;

                if let Ok(cwd) =
                    env::current_dir().and_then(|dir| dir.canonicalize())
                {
                    if let Ok(relative_path) = path.strip_prefix(cwd) {
                        path = relative_path.to_path_buf();
                    }
                }

                Ok((content, path))
            };

        // Look for the included file in the directory at the top of the
        // include stack.
        if let Some(dir) =
            self.include_stack.last().and_then(|path| path.parent())
        {
            if let Ok(result) = read_file(dir.join(include.file_name)) {
                return Ok(result);
            }
        }

        // If one or more include directory were specified, try to find the
        // included file in them, in the order they were specified. Otherwise,
        // try to find the included file in the current directory.
        if let Some(include_dirs) = &self.include_dirs {
            if let Some(result) = include_dirs
                .iter()
                .find_map(|dir| read_file(dir.join(include.file_name)).ok())
            {
                Ok(result)
            } else {
                Err(IncludeNotFound::build(
                    &self.report_builder,
                    include.file_name.to_string(),
                    self.report_builder.span_to_code_loc(include.span()),
                ))
            }
        } else {
            read_file(PathBuf::from(include.file_name)).map_err(|err| {
                if err.kind() == io::ErrorKind::NotFound {
                    IncludeNotFound::build(
                        &self.report_builder,
                        include.file_name.to_string(),
                        self.report_builder.span_to_code_loc(include.span()),
                    )
                } else {
                    IncludeError::build(
                        &self.report_builder,
                        self.report_builder.span_to_code_loc(include.span()),
                        err.to_string(),
                    )
                }
            })
        }
    }
}

impl Compiler<'_> {
    fn c_items<'a, I>(&mut self, items: I)
    where
        I: Iterator<Item = &'a ast::Item<'a>>,
    {
        let mut already_imported = FxHashMap::default();

        for item in items {
            match item {
                ast::Item::Import(import) => {
                    // Checks that all imported modules actually exist, and
                    // raise warnings in case of duplicated imports within
                    // the same source file. For each module add a symbol to
                    // the current namespace.
                    if let Some(existing_import) = already_imported.insert(
                        &import.module_name,
                        self.report_builder.span_to_code_loc(import.span()),
                    ) {
                        let duplicated_import = self
                            .report_builder
                            .span_to_code_loc(import.span());

                        let mut warning = warnings::DuplicateImport::build(
                            &self.report_builder,
                            import.module_name.to_string(),
                            duplicated_import.clone(),
                            existing_import,
                        );

                        warning.report_mut().patch(duplicated_import, "");

                        self.warnings.add(|| warning)
                    }
                    // Import the module. This updates `self.root_struct` if
                    // necessary.
                    if let Err(err) = self.c_import(import) {
                        self.errors.push(err);
                    }
                }
                ast::Item::Include(include) => {
                    // Return an error if includes are disabled
                    if !self.includes_enabled {
                        self.errors.push(IncludeNotAllowed::build(
                            &self.report_builder,
                            self.report_builder
                                .span_to_code_loc(include.span()),
                        ));
                        continue;
                    }

                    let (included_src, included_path) =
                        match self.read_included_file(include) {
                            Ok(included) => included,
                            Err(err) => {
                                self.errors.push(err);
                                continue;
                            }
                        };

                    if self.include_stack.contains(&included_path) {
                        self.errors.push(CircularIncludes::build(
                            &self.report_builder,
                            self.report_builder
                                .span_to_code_loc(include.span()),
                            Some(format!(
                                "include dependencies:\n{}",
                                self.include_stack
                                    .iter()
                                    .enumerate()
                                    .map(|(i, path)| format!(
                                        "{:>width$}↳ {}",
                                        "",
                                        path.display(),
                                        width = i * 2
                                    ))
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            )),
                        ));
                        continue;
                    }

                    // Save the current source ID from the report builder in
                    // order to restore it later. Any recursive call to
                    // `add_source` will change the current source ID, and we
                    // need to restore after `add_source` returns.
                    let source_id =
                        self.report_builder.get_current_source_id().unwrap();

                    let source_code =
                        SourceCode::from(included_src.as_slice()).with_origin(
                            // In Windows the paths separators are backslashes, but we
                            // want to use slashes.
                            included_path.to_str().unwrap().replace("\\", "/"),
                        );

                    self.include_stack.push(included_path);

                    // Any error generated while processing the included source
                    // code will be added to `self.errors`. The error returned
                    // by `add_source` is simply the first of the added errors,
                    // we don't need to handle the error here.
                    let _ = self.add_source(source_code);

                    // Restore the current source ID to the value it had before
                    // calling `add_source`.
                    self.report_builder.set_current_source_id(source_id);

                    self.include_stack.pop().unwrap();
                }
                ast::Item::Rule(rule) => {
                    if let Err(err) = self.c_rule(rule) {
                        self.errors.push(err);
                    }
                }
            }
        }
    }

    fn c_rule(&mut self, rule: &ast::Rule) -> Result<(), CompileError> {
        // Check if another rule, module or variable has the same identifier
        // and return an error in that case.
        self.check_for_existing_identifier(&rule.identifier)?;

        // Check that rule tags, if any, doesn't contain duplicates.
        if let Some(tags) = &rule.tags {
            self.check_for_duplicate_tags(tags.as_slice())?;
        }

        // Check the rule with all the linters.
        for linter in self.linters.iter() {
            match linter.check(&self.report_builder, rule) {
                LinterResult::Ok => {}
                LinterResult::Warn(warning) => {
                    self.warnings.add(|| warning);
                }
                LinterResult::Warns(warnings) => {
                    for warning in warnings {
                        self.warnings.add(|| warning);
                    }
                }
                LinterResult::Err(err) => return Err(err),
            }
        }

        // Take snapshot of the current compiler state. In case of error
        // compiling the current rule this snapshot allows restoring the
        // compiler to the state it had before starting compiling the rule.
        // This way we don't leave too much junk, like atoms, or sub-patterns
        // corresponding to failed rules. However, there is some junk left
        // behind in `ident_pool` and `lit_pool`, because once a string is
        // added to one of these pools it can't be removed.
        let snapshot = self.take_snapshot();

        let tags: Vec<IdentId> = rule
            .tags
            .iter()
            .flatten()
            .map(|t| self.ident_pool.get_or_intern(t.name))
            .collect();

        // Helper function that converts from `ast::MetaValue` to
        // `compiler::rules::MetaValue`.
        let mut convert_meta_value = |value: &ast::MetaValue| match value {
            ast::MetaValue::Integer((i, _)) => MetaValue::Integer(*i),
            ast::MetaValue::Float((f, _)) => MetaValue::Float(*f),
            ast::MetaValue::Bool((b, _)) => MetaValue::Bool(*b),
            ast::MetaValue::String((s, _)) => {
                MetaValue::String(self.lit_pool.get_or_intern(s))
            }
            ast::MetaValue::Bytes((s, _)) => {
                MetaValue::Bytes(self.lit_pool.get_or_intern(s))
            }
        };

        // Build a vector of pairs (IdentId, MetaValue) for every meta defined
        // in the rule.
        let metadata = rule
            .meta
            .iter()
            .flatten()
            .map(|m| {
                (
                    self.ident_pool.get_or_intern(m.identifier.name),
                    convert_meta_value(&m.value),
                )
            })
            .collect();

        let mut rule_patterns = Vec::new();

        let mut ctx = CompileContext {
            ir: &mut self.ir,
            relaxed_re_syntax: self.relaxed_re_syntax,
            error_on_slow_loop: self.error_on_slow_loop,
            one_shot_symbol_table: None,
            symbol_table: &mut self.symbol_table,
            report_builder: &self.report_builder,
            current_rule_patterns: &mut rule_patterns,
            warnings: &mut self.warnings,
            vars: VarStack::new(),
            for_of_depth: 0,
            features: &self.features,
            loop_iteration_multiplier: 1,
        };

        // Convert the patterns from AST to IR. This populates the
        // `ctx.current_rule_patterns` vector.
        if let Err(err) = patterns_from_ast(&mut ctx, rule) {
            drop(ctx);
            self.restore_snapshot(snapshot);
            return Err(err);
        }

        // Convert the condition from AST to IR. Also updates the patterns
        // with information about whether they are used in the condition and
        // if they are anchored or not.
        let condition = rule_condition_from_ast(&mut ctx, rule);

        drop(ctx);

        // Search for patterns that are very common byte repetitions like:
        //
        //   00 00 00 00 00 00 ....
        //   90 90 09 90 90 90 ....
        //   FF FF FF FF FF FF ....
        //
        // Raise a warning when such a pattern is found, except in the
        // following cases:
        //
        // 1) When the pattern is anchored, because anchored pattern can appear
        //    only at a fixed offset and are not searched by Aho-Corasick.
        //
        // 2) When the pattern has attributes: xor, fullword, base64 or
        //    base64wide, because in those cases the real pattern is not that
        //    common.
        //
        // Note: this can't be done before calling `rule_condition_from_ast`,
        // because we don't know which patterns are anchored until the condition
        // is processed.
        for pat in rule_patterns.iter() {
            if pat.anchored_at().is_none()
                && !pat.pattern().flags().intersects(
                    PatternFlags::Xor
                        | PatternFlags::Fullword
                        | PatternFlags::Base64
                        | PatternFlags::Base64Wide,
                )
            {
                let literal_bytes = match pat.pattern() {
                    Pattern::Text(lit) => Some(lit.text.as_bytes()),
                    Pattern::Regexp(re) => re.hir.as_literal_bytes(),
                    Pattern::Hex(re) => re.hir.as_literal_bytes(),
                };
                if let Some(literal_bytes) = literal_bytes {
                    if Self::common_byte_repetition(literal_bytes) {
                        self.warnings.add(|| {
                            warnings::SlowPattern::build(
                                &self.report_builder,
                                self.report_builder
                                    .span_to_code_loc(pat.span().clone()),
                                None,
                            )
                        });
                    }
                }
            }
        }

        // In case of error, restore the compiler to the state it was before
        // entering this function. Also, if the error is due to an unknown
        // identifier, but the identifier is one of the unsupported modules,
        // the error is tolerated and a warning is issued instead.
        let mut condition = match condition {
            Ok(condition) => condition,
            Err(CompileError::UnknownIdentifier(unknown))
                if self.ignored_rules.contains_key(unknown.identifier())
                    || self.ignored_modules.contains(unknown.identifier()) =>
            {
                self.restore_snapshot(snapshot);

                if let Some(module_name) =
                    self.ignored_rules.get(unknown.identifier())
                {
                    self.warnings.add(|| {
                        warnings::IgnoredRule::build(
                            &self.report_builder,
                            module_name.clone(),
                            rule.identifier.name.to_string(),
                            unknown.identifier_location().clone(),
                        )
                    });
                    self.ignored_rules.insert(
                        rule.identifier.name.to_string(),
                        module_name.clone(),
                    );
                } else {
                    self.warnings.add(|| {
                        warnings::IgnoredModule::build(
                            &self.report_builder,
                            unknown.identifier().to_string(),
                            unknown.identifier_location().clone(),
                            Some(format!(
                                "the whole rule `{}` will be ignored",
                                rule.identifier.name
                            )),
                        )
                    });
                    self.ignored_rules.insert(
                        rule.identifier.name.to_string(),
                        unknown.identifier().to_string(),
                    );
                }

                return Ok(());
            }
            Err(err) => {
                self.restore_snapshot(snapshot);
                return Err(err);
            }
        };

        if self.hoisting {
            condition = self.ir.hoisting();
        }

        // Analyze the condition and determine the bounds it imposes to
        // `filesize`, if any.
        let filesize_bounds = self.ir.filesize_bounds();

        // Set the bounds to all patterns in the rule. This must be done
        // before assigning the PatternId to each pattern, as the filesize
        // bounds are taken into account when determining if the pattern
        // is unique or re-used from a previous rule.
        if !filesize_bounds.unbounded() {
            for pattern in &mut rule_patterns {
                pattern.pattern_mut().set_filesize_bounds(&filesize_bounds);
            }
        }

        if let Some(w) = &mut self.ir_writer {
            writeln!(w, "RULE {}", rule.identifier.name).unwrap();
            writeln!(w, "{:?}", self.ir).unwrap();
            if !filesize_bounds.unbounded() {
                writeln!(w, "{filesize_bounds:?}\n",).unwrap();
            }
        }

        let mut pattern_ids = Vec::with_capacity(rule_patterns.len());
        let mut patterns = Vec::with_capacity(rule_patterns.len());
        let mut pending_patterns = HashSet::new();
        let mut num_private_patterns = 0;

        for pattern in &rule_patterns {
            // Raise error is some pattern was not used, except if the pattern
            // identifier starts with underscore.
            if !pattern.in_use() && !pattern.identifier().starts_with("$_") {
                self.restore_snapshot(snapshot);
                return Err(UnusedPattern::build(
                    &self.report_builder,
                    pattern.identifier().name.to_string(),
                    self.report_builder
                        .span_to_code_loc(pattern.identifier().span()),
                ));
            }

            if pattern.pattern().flags().contains(PatternFlags::Private) {
                num_private_patterns += 1;
            }

            // Check if this pattern has been declared before, in this rule or
            // in some other rule. In such cases the pattern ID is re-used, and
            // we don't need to process (i.e: extract atoms and add them to
            // Aho-Corasick automaton) the pattern again. Two patterns are
            // considered equal if they are exactly the same, including any
            // modifiers associated to the pattern, both are non-anchored
            // or anchored at the same file offset, and if they have the same
            // file size bounds.
            let pattern_id =
                match self.patterns.entry(pattern.pattern().clone()) {
                    // The pattern already exists, return the existing ID.
                    Entry::Occupied(entry) => *entry.get(),
                    // The pattern didn't exist.
                    Entry::Vacant(entry) => {
                        let pattern_id = self.next_pattern_id;
                        self.next_pattern_id.incr(1);
                        pending_patterns.insert(pattern_id);
                        entry.insert(pattern_id);
                        pattern_id
                    }
                };

            let kind = match pattern.pattern() {
                Pattern::Text(_) => PatternKind::Text,
                Pattern::Regexp(_) => PatternKind::Regexp,
                Pattern::Hex(_) => PatternKind::Hex,
            };

            patterns.push(PatternInfo {
                kind,
                pattern_id,
                ident_id: self
                    .ident_pool
                    .get_or_intern(pattern.identifier().name),
                is_private: pattern
                    .pattern()
                    .flags()
                    .contains(PatternFlags::Private),
            });

            pattern_ids.push(pattern_id);
        }

        // The RuleId for the new rule is current length of `self.rules`. The
        // first rule has RuleId = 0.
        let rule_id = RuleId::from(self.rules.len());

        self.rules.push(RuleInfo {
            tags,
            metadata,
            patterns,
            num_private_patterns,
            is_global: rule.flags.contains(RuleFlags::Global),
            is_private: rule.flags.contains(RuleFlags::Private),
            namespace_id: self.current_namespace.id,
            namespace_ident_id: self.current_namespace.ident_id,
            ident_id: self.ident_pool.get_or_intern(rule.identifier.name),
            ident_ref: self
                .report_builder
                .span_to_code_loc(rule.identifier.span()),
        });

        // Process the patterns in the rule. This extracts the best atoms
        // from each pattern, adding them to the `self.atoms` vector, it
        // also creates one or more sub-patterns per pattern and adds them
        // to `self.sub_patterns`
        for (pattern_id, pattern) in
            izip!(pattern_ids.iter(), rule_patterns.into_iter())
        {
            if pending_patterns.contains(pattern_id) {
                let pattern_span = pattern.span().clone();
                match pattern.into_pattern() {
                    Pattern::Text(pattern) => {
                        self.c_literal_pattern(*pattern_id, pattern);
                    }
                    Pattern::Regexp(pattern) | Pattern::Hex(pattern) => {
                        if let Err(err) = self.c_regexp_pattern(
                            *pattern_id,
                            pattern,
                            pattern_span,
                        ) {
                            self.restore_snapshot(snapshot);
                            return Err(err);
                        }
                    }
                };
                if !filesize_bounds.unbounded()
                    && self
                        .filesize_bounds
                        .insert(*pattern_id, filesize_bounds.clone())
                        .is_some()
                {
                    // This should not happen.
                    panic!("modifying the file size bounds of an existing pattern")
                }
                pending_patterns.remove(pattern_id);
            }
        }

        // Create a new symbol of bool type for the rule.
        let new_symbol = Symbol::Rule {
            rule_id,
            is_global: rule.flags.contains(RuleFlags::Global),
        };

        // Insert the symbol in the symbol table corresponding to the
        // current namespace. This must be done after every fallible function
        // has been called; once the symbol is inserted in the symbol table,
        // it can't be undone.
        let existing_symbol = self
            .current_namespace
            .symbols
            .as_ref()
            .borrow_mut()
            .insert(rule.identifier.name, new_symbol);

        // No other symbol with the same identifier should exist.
        assert!(existing_symbol.is_none());

        // The last step is emitting the WASM code corresponding to the rule's
        // condition. This is done after every fallible function has been called
        // because once the code is emitted it cannot be undone, which means
        // that if this function fails after emitting the code, some code debris
        // will remain in the WASM module.
        let mut ctx = EmitContext {
            current_rule: self.rules.last_mut().unwrap(),
            lit_pool: &mut self.lit_pool,
            regexp_pool: &mut self.regexp_pool,
            wasm_symbols: &self.wasm_symbols,
            wasm_exports: &self.wasm_exports,
            exception_handler_stack: Vec::new(),
            lookup_list: Vec::new(),
            emit_search_for_pattern_stack: Vec::new(),
        };

        emit_rule_condition(
            &mut ctx,
            &self.ir,
            rule_id,
            condition,
            &mut self.wasm_mod,
        );

        Ok(())
    }

    fn c_import(&mut self, import: &Import) -> Result<(), CompileError> {
        let module_name = import.module_name;
        let module = BUILTIN_MODULES.get(module_name);

        // Does a module with the given name actually exist? ...
        if module.is_none() {
            // The module does not exist, but it is included in the list
            // of unsupported modules. In such cases we don't raise an error,
            // only a warning.
            return if self.ignored_modules.iter().any(|m| m == module_name) {
                self.warnings.add(|| {
                    warnings::IgnoredModule::build(
                        &self.report_builder,
                        module_name.to_string(),
                        self.report_builder.span_to_code_loc(import.span()),
                        None,
                    )
                });
                Ok(())
            } else {
                // The module does not exist, and is not explicitly added to
                // the list of unsupported modules, that's an error.
                Err(UnknownModule::build(
                    &self.report_builder,
                    module_name.to_string(),
                    self.report_builder.span_to_code_loc(import.span()),
                ))
            };
        }

        // Yes, module exists.
        let module = module.unwrap();

        // If the module has not been added to `self.root_struct` and
        // `self.imported_modules`, do it.
        if !self.root_struct.has_field(module_name) {
            // Add the module to the list of imported modules.
            self.imported_modules
                .push(self.ident_pool.get_or_intern(module_name));

            // Create the `Struct` that describes the module.
            let module_struct = Rc::<Struct>::from(module);

            // Insert the module in the struct that contains all imported
            // modules. This struct contains all modules imported, from
            // all namespaces. Panic if the module was already in the struct.
            if self
                .root_struct
                .add_field(module_name, TypeValue::Struct(module_struct))
                .is_some()
            {
                panic!("duplicate module `{module_name}`")
            }
        }

        let mut symbol_table =
            self.current_namespace.symbols.as_ref().borrow_mut();

        // Create a symbol for the module and insert it in the symbol
        // table for this namespace, if it doesn't exist.
        if !symbol_table.contains(module_name) {
            symbol_table.insert(
                module_name,
                self.root_struct.lookup(module_name).unwrap(),
            );
        }

        // Is the module banned? If yes, produce an error. Notice however that
        // this check is done after the module has been added to the symbol
        // table because we don't want additional errors due to undefined
        // identifiers when the banned module is used in some rule condition.
        if let Some((error_title, error_msg)) =
            self.banned_modules.get(module_name)
        {
            return Err(CustomError::build(
                &self.report_builder,
                error_title.clone(),
                error_msg.clone(),
                self.report_builder.span_to_code_loc(import.span()),
            ));
        }

        Ok(())
    }

    fn c_literal_pattern(
        &mut self,
        pattern_id: PatternId,
        pattern: LiteralPattern,
    ) {
        let full_word = pattern.flags.contains(PatternFlags::Fullword);
        let mut flags = SubPatternFlags::empty();

        if full_word {
            flags.insert(SubPatternFlags::FullwordLeft);
            flags.insert(SubPatternFlags::FullwordRight);
        }

        // Depending on the combination of `ascii` and `wide` modifiers, the
        // `main_patterns` vector will contain either the pattern's `ascii`
        // version, the `wide` version, or both. Each item in `main_patterns`
        // also contains the best atom for the pattern.
        let mut main_patterns = Vec::new();
        let wide_pattern;

        if pattern.flags.contains(PatternFlags::Wide) {
            wide_pattern = make_wide(pattern.text.as_bytes());
            main_patterns.push((
                wide_pattern.as_slice(),
                best_atom_in_bytes(wide_pattern.as_slice()),
                flags | SubPatternFlags::Wide,
            ));
        }

        if pattern.flags.contains(PatternFlags::Ascii) {
            main_patterns.push((
                pattern.text.as_bytes(),
                best_atom_in_bytes(pattern.text.as_bytes()),
                flags,
            ));
        }

        for (main_pattern, best_atom, flags) in main_patterns {
            let pattern_lit_id = self.lit_pool.get_or_intern(main_pattern);

            if pattern.flags.contains(PatternFlags::Xor) {
                // When `xor` is used, `base64`, `base64wide` and `nocase` are
                // not accepted.
                debug_assert!(!pattern.flags.contains(
                    PatternFlags::Base64
                        | PatternFlags::Base64Wide
                        | PatternFlags::Nocase,
                ));

                let xor_range = pattern.xor_range.clone().unwrap();
                self.add_sub_pattern(
                    pattern_id,
                    SubPattern::Xor { pattern: pattern_lit_id, flags },
                    best_atom.xor_combinations(xor_range),
                    SubPatternAtom::from_atom,
                );
            } else if pattern.flags.contains(PatternFlags::Nocase) {
                // When `nocase` is used, `base64`, `base64wide` and `xor` are
                // not accepted.
                debug_assert!(!pattern.flags.contains(
                    PatternFlags::Base64
                        | PatternFlags::Base64Wide
                        | PatternFlags::Xor,
                ));

                self.add_sub_pattern(
                    pattern_id,
                    SubPattern::Literal {
                        pattern: pattern_lit_id,
                        flags: flags | SubPatternFlags::Nocase,
                        anchored_at: None,
                    },
                    best_atom.case_combinations(),
                    SubPatternAtom::from_atom,
                );
            }
            // Used `base64`, or `base64wide`, or both.
            else if pattern
                .flags
                .intersects(PatternFlags::Base64 | PatternFlags::Base64Wide)
            {
                // When `base64` or `base64wide` are used, `xor`, `fullword`
                // and `nocase` are not accepted.
                debug_assert!(!pattern.flags.contains(
                    PatternFlags::Xor
                        | PatternFlags::Fullword
                        | PatternFlags::Nocase,
                ));

                if pattern.flags.contains(PatternFlags::Base64) {
                    for (padding, base64_pattern) in base64_patterns(
                        main_pattern,
                        pattern.base64_alphabet.as_deref(),
                    ) {
                        let sub_pattern = if let Some(alphabet) =
                            pattern.base64_alphabet.as_deref()
                        {
                            SubPattern::CustomBase64 {
                                pattern: pattern_lit_id,
                                alphabet: self
                                    .lit_pool
                                    .get_or_intern(alphabet),
                                padding,
                            }
                        } else {
                            SubPattern::Base64 {
                                pattern: pattern_lit_id,
                                padding,
                            }
                        };

                        self.add_sub_pattern(
                            pattern_id,
                            sub_pattern,
                            iter::once({
                                let mut atom = best_atom_in_bytes(
                                    base64_pattern.as_slice(),
                                );
                                // Atoms for base64 patterns are always
                                // inexact, they require verification.
                                atom.make_inexact();
                                atom
                            }),
                            SubPatternAtom::from_atom,
                        );
                    }
                }

                if pattern.flags.contains(PatternFlags::Base64Wide) {
                    for (padding, base64_pattern) in base64_patterns(
                        main_pattern,
                        pattern.base64wide_alphabet.as_deref(),
                    ) {
                        let sub_pattern = if let Some(alphabet) =
                            pattern.base64wide_alphabet.as_deref()
                        {
                            SubPattern::CustomBase64Wide {
                                pattern: pattern_lit_id,
                                alphabet: self
                                    .lit_pool
                                    .get_or_intern(alphabet),
                                padding,
                            }
                        } else {
                            SubPattern::Base64Wide {
                                pattern: pattern_lit_id,
                                padding,
                            }
                        };

                        let wide = make_wide(base64_pattern.as_slice());

                        self.add_sub_pattern(
                            pattern_id,
                            sub_pattern,
                            iter::once({
                                let mut atom =
                                    best_atom_in_bytes(wide.as_slice());
                                // Atoms for base64 patterns are always
                                // inexact, they require verification.
                                atom.make_inexact();
                                atom
                            }),
                            SubPatternAtom::from_atom,
                        );
                    }
                }
            } else {
                self.add_sub_pattern(
                    pattern_id,
                    SubPattern::Literal {
                        pattern: pattern_lit_id,
                        anchored_at: pattern.anchored_at,
                        flags,
                    },
                    iter::once(best_atom),
                    SubPatternAtom::from_atom,
                );
            }
        }
    }

    fn c_regexp_pattern(
        &mut self,
        pattern_id: PatternId,
        pattern: RegexpPattern,
        span: Span,
    ) -> Result<(), CompileError> {
        // Try splitting the regexp into multiple chained sub-patterns if it
        // contains large gaps. For example, `{ 01 02 03 [-] 04 05 06 }` is
        // split into `{ 01 02 03 }` and `{ 04 05 06 }`, where `{ 04 05 06 }`
        // is chained to `{ 01 02 03 }`.
        //
        // If the regexp can't be split then `head` is the whole regexp.
        let (head, tail) = pattern.hir.split_at_large_gaps();

        if !tail.is_empty() {
            // The pattern was split into multiple chained regexps.
            return self.c_chain(
                pattern_id,
                &head,
                &tail,
                pattern.flags,
                span,
            );
        }

        if head.is_alternation_literal() {
            // The pattern is either a literal, or an alternation of literals.
            // Examples:
            //   /foo/
            //   /foo|bar|baz/
            //   { 01 02 03 }
            //   { (01 02 03 | 04 05 06 ) }
            return self.c_alternation_literal(
                pattern_id,
                head,
                pattern.anchored_at,
                pattern.flags,
            );
        }

        // If this point is reached, this is a pattern that can't be split into
        // multiple chained patterns, and is neither a literal or alternation
        // of literals. Most patterns fall in this category.
        let mut flags = SubPatternFlags::empty();

        if pattern.flags.contains(PatternFlags::Nocase) {
            flags.insert(SubPatternFlags::Nocase);
        }

        if pattern.flags.contains(PatternFlags::Fullword) {
            flags.insert(SubPatternFlags::FullwordLeft);
            flags.insert(SubPatternFlags::FullwordRight);
        }

        if matches!(head.is_greedy(), Some(true)) {
            flags.insert(SubPatternFlags::GreedyRegexp);
        }

        let (atoms, is_fast_regexp) = self.c_regexp(&head, span)?;

        if is_fast_regexp {
            flags.insert(SubPatternFlags::FastRegexp);
        }

        if pattern.flags.contains(PatternFlags::Wide) {
            self.add_sub_pattern(
                pattern_id,
                SubPattern::Regexp { flags: flags | SubPatternFlags::Wide },
                atoms.iter().cloned().map(|atom| atom.make_wide()),
                SubPatternAtom::from_regexp_atom,
            );
        }

        if pattern.flags.contains(PatternFlags::Ascii) {
            self.add_sub_pattern(
                pattern_id,
                SubPattern::Regexp { flags },
                atoms.into_iter(),
                SubPatternAtom::from_regexp_atom,
            );
        }

        Ok(())
    }

    fn c_alternation_literal(
        &mut self,
        pattern_id: PatternId,
        hir: re::hir::Hir,
        anchored_at: Option<usize>,
        flags: PatternFlags,
    ) -> Result<(), CompileError> {
        let ascii = flags.contains(PatternFlags::Ascii);
        let wide = flags.contains(PatternFlags::Wide);
        let case_insensitive = flags.contains(PatternFlags::Nocase);
        let full_word = flags.contains(PatternFlags::Fullword);

        let mut flags = SubPatternFlags::empty();

        if case_insensitive {
            flags.insert(SubPatternFlags::Nocase);
        }

        if full_word {
            flags.insert(SubPatternFlags::FullwordLeft);
            flags.insert(SubPatternFlags::FullwordRight);
        }

        let mut process_literal = |literal: &hir::Literal, wide: bool| {
            let pattern_lit_id =
                self.intern_literal(literal.0.as_bytes(), wide);

            let best_atom = best_atom_in_bytes(
                self.lit_pool.get_bytes(pattern_lit_id).unwrap(),
            );

            let flags =
                if wide { flags | SubPatternFlags::Wide } else { flags };

            let sub_pattern = SubPattern::Literal {
                pattern: pattern_lit_id,
                anchored_at,
                flags,
            };

            if case_insensitive {
                self.add_sub_pattern(
                    pattern_id,
                    sub_pattern,
                    best_atom.case_combinations(),
                    SubPatternAtom::from_atom,
                );
            } else {
                self.add_sub_pattern(
                    pattern_id,
                    sub_pattern,
                    iter::once(best_atom),
                    SubPatternAtom::from_atom,
                );
            }
        };

        let inner;

        let hir = if let hir::HirKind::Capture(group) = hir.kind() {
            group.sub.as_ref()
        } else {
            inner = hir.into_inner();
            &inner
        };

        match hir.kind() {
            hir::HirKind::Literal(literal) => {
                if ascii {
                    process_literal(literal, false);
                }
                if wide {
                    process_literal(literal, true);
                }
            }
            hir::HirKind::Alternation(literals) => {
                let literals = literals
                    .iter()
                    .map(|l| cast!(l.kind(), hir::HirKind::Literal));
                for literal in literals {
                    if ascii {
                        process_literal(literal, false);
                    }
                    if wide {
                        process_literal(literal, true);
                    }
                }
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn c_chain(
        &mut self,
        pattern_id: PatternId,
        leading: &re::hir::Hir,
        trailing: &[ChainedPattern],
        flags: PatternFlags,
        span: Span,
    ) -> Result<(), CompileError> {
        let ascii = flags.contains(PatternFlags::Ascii);
        let wide = flags.contains(PatternFlags::Wide);
        let case_insensitive = flags.contains(PatternFlags::Nocase);
        let full_word = flags.contains(PatternFlags::Fullword);

        let mut common_flags = SubPatternFlags::empty();

        if case_insensitive {
            common_flags.insert(SubPatternFlags::Nocase);
        }

        if matches!(leading.is_greedy(), Some(true)) {
            common_flags.insert(SubPatternFlags::GreedyRegexp);
        }

        let mut prev_sub_pattern_ascii = SubPatternId(0);
        let mut prev_sub_pattern_wide = SubPatternId(0);

        if let hir::HirKind::Literal(literal) = leading.kind() {
            let mut flags = common_flags;

            if full_word {
                flags.insert(SubPatternFlags::FullwordLeft);
            }

            if ascii {
                prev_sub_pattern_ascii =
                    self.c_literal_chain_head(pattern_id, literal, flags);
            }

            if wide {
                prev_sub_pattern_wide = self.c_literal_chain_head(
                    pattern_id,
                    literal,
                    flags | SubPatternFlags::Wide,
                );
            };
        } else {
            let mut flags = common_flags;

            let (atoms, is_fast_regexp) =
                self.c_regexp(leading, span.clone())?;

            if is_fast_regexp {
                flags.insert(SubPatternFlags::FastRegexp);
            }

            if full_word {
                flags.insert(SubPatternFlags::FullwordLeft);
            }

            if wide {
                prev_sub_pattern_wide = self.add_sub_pattern(
                    pattern_id,
                    SubPattern::RegexpChainHead {
                        flags: flags | SubPatternFlags::Wide,
                    },
                    atoms.iter().cloned().map(|atom| atom.make_wide()),
                    SubPatternAtom::from_regexp_atom,
                );
            }

            if ascii {
                prev_sub_pattern_ascii = self.add_sub_pattern(
                    pattern_id,
                    SubPattern::RegexpChainHead { flags },
                    atoms.into_iter(),
                    SubPatternAtom::from_regexp_atom,
                );
            }
        }

        for (i, p) in trailing.iter().enumerate() {
            let mut flags = common_flags;

            // The last pattern in the chain has the `LastInChain` flag and
            // the `FullwordRight` if the original pattern was `Fullword`.
            // Patterns in the middle of the chain won't have either of these
            // flags.
            if i == trailing.len() - 1 {
                flags.insert(SubPatternFlags::LastInChain);
                if full_word {
                    flags.insert(SubPatternFlags::FullwordRight);
                }
            }

            if let hir::HirKind::Literal(literal) = p.hir.kind() {
                if wide {
                    prev_sub_pattern_wide = self.c_literal_chain_tail(
                        pattern_id,
                        literal,
                        prev_sub_pattern_wide,
                        p.gap.clone(),
                        flags | SubPatternFlags::Wide,
                    );
                };
                if ascii {
                    prev_sub_pattern_ascii = self.c_literal_chain_tail(
                        pattern_id,
                        literal,
                        prev_sub_pattern_ascii,
                        p.gap.clone(),
                        flags,
                    );
                }
            } else {
                if matches!(p.hir.is_greedy(), Some(true)) {
                    flags.insert(SubPatternFlags::GreedyRegexp);
                }

                let (atoms, is_fast_regexp) =
                    self.c_regexp(&p.hir, span.clone())?;

                if is_fast_regexp {
                    flags.insert(SubPatternFlags::FastRegexp);
                }

                if wide {
                    prev_sub_pattern_wide = self.add_sub_pattern(
                        pattern_id,
                        SubPattern::RegexpChainTail {
                            chained_to: prev_sub_pattern_wide,
                            gap: p.gap.clone(),
                            flags: flags | SubPatternFlags::Wide,
                        },
                        atoms.iter().cloned().map(|atom| atom.make_wide()),
                        SubPatternAtom::from_regexp_atom,
                    )
                }

                if ascii {
                    prev_sub_pattern_ascii = self.add_sub_pattern(
                        pattern_id,
                        SubPattern::RegexpChainTail {
                            chained_to: prev_sub_pattern_ascii,
                            gap: p.gap.clone(),
                            flags,
                        },
                        atoms.into_iter(),
                        SubPatternAtom::from_regexp_atom,
                    );
                }
            }
        }

        Ok(())
    }

    fn c_regexp(
        &mut self,
        hir: &re::hir::Hir,
        span: Span,
    ) -> Result<(Vec<re::RegexpAtom>, bool), CompileError> {
        // When the `fast-regexp` feature is enabled, try to compile the regexp
        // for `FastVM` first, if it fails with `Error::FastIncompatible`, the
        // regexp is not compatible for `FastVM` and `PikeVM` must be used
        // instead.
        #[cfg(feature = "fast-regexp")]
        let (result, is_fast_regexp) = match re::fast::Compiler::new()
            .compile(hir, &mut self.re_code)
        {
            Err(re::Error::FastIncompatible) => (
                re::thompson::Compiler::new().compile(hir, &mut self.re_code),
                false,
            ),
            result => (result, true),
        };

        #[cfg(not(feature = "fast-regexp"))]
        let (result, is_fast_regexp) = (
            re::thompson::Compiler::new().compile(hir, &mut self.re_code),
            false,
        );

        let re_atoms = result.map_err(|err| {
            InvalidRegexp::build(
                &self.report_builder,
                err.to_string(),
                self.report_builder.span_to_code_loc(span.clone()),
                None,
            )
        })?;

        if matches!(hir.minimum_len(), Some(0)) {
            return Err(InvalidRegexp::build(
                &self.report_builder,
                "this regexp can match empty strings".to_string(),
                self.report_builder.span_to_code_loc(span),
                None,
            ));
        }

        let (slow_pattern, note) =
            match re_atoms.iter().map(|re_atom| re_atom.atom.len()).minmax() {
                // No atoms, slow pattern.
                MinMaxResult::NoElements => (true, None),
                // Only one atom of len 0.
                MinMaxResult::OneElement(0) => (
                    true,
                    Some(
                        "this is an exceptionally extreme case that may severely degrade scanning throughput"
                            .to_string(),
                    ),
                ),
                // Only one atom shorter than 2 bytes, slow pattern.
                MinMaxResult::OneElement(len) if len < 2 => (true, None),
                // More than one atom, at least one is shorter than 2 bytes.
                MinMaxResult::MinMax(min, _) if min < 2 => (true, None),
                // More than 2700 atoms, all with exactly 2 bytes.
                // Why 2700?. The larger the number of atoms the higher the
                // odds of finding one of them in the data, which slows down
                // the scan. The regex [A-Za-z]{N,} (with N>=2) produces
                // (26+26)^2 = 2704 atoms. So, 2700 is large enough, but
                // produces a warning with the aforementioned regex.
                MinMaxResult::MinMax(2, 2) if re_atoms.len() > 2700 => {
                    (true, None)
                }
                // In all other cases the pattern is not slow.
                _ => (false, None),
            };

        if slow_pattern {
            if self.error_on_slow_pattern {
                return Err(errors::SlowPattern::build(
                    &self.report_builder,
                    self.report_builder.span_to_code_loc(span),
                    note,
                ));
            } else {
                self.warnings.add(|| {
                    warnings::SlowPattern::build(
                        &self.report_builder,
                        self.report_builder.span_to_code_loc(span),
                        note,
                    )
                });
            }
        }

        Ok((re_atoms, is_fast_regexp))
    }

    fn c_literal_chain_head(
        &mut self,
        pattern_id: PatternId,
        literal: &hir::Literal,
        flags: SubPatternFlags,
    ) -> SubPatternId {
        let pattern_lit_id = self.intern_literal(
            literal.0.as_bytes(),
            flags.contains(SubPatternFlags::Wide),
        );
        self.add_sub_pattern(
            pattern_id,
            SubPattern::LiteralChainHead { pattern: pattern_lit_id, flags },
            extract_atoms(
                self.lit_pool.get_bytes(pattern_lit_id).unwrap(),
                flags,
            ),
            SubPatternAtom::from_atom,
        )
    }

    fn c_literal_chain_tail(
        &mut self,
        pattern_id: PatternId,
        literal: &hir::Literal,
        chained_to: SubPatternId,
        gap: ChainedPatternGap,
        flags: SubPatternFlags,
    ) -> SubPatternId {
        let pattern_lit_id = self.intern_literal(
            literal.0.as_bytes(),
            flags.contains(SubPatternFlags::Wide),
        );
        self.add_sub_pattern(
            pattern_id,
            SubPattern::LiteralChainTail {
                pattern: pattern_lit_id,
                chained_to,
                gap,
                flags,
            },
            extract_atoms(
                self.lit_pool.get_bytes(pattern_lit_id).unwrap(),
                flags,
            ),
            SubPatternAtom::from_atom,
        )
    }
}

impl fmt::Debug for Compiler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Compiler")
    }
}

impl Default for Compiler<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// ID associated to each identifier in the identifiers pool.
#[derive(Eq, PartialEq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct IdentId(u32);

impl From<u32> for IdentId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<IdentId> for u32 {
    fn from(v: IdentId) -> Self {
        v.0
    }
}

/// ID associated to each literal string in the literals pool.
#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct LiteralId(u32);

impl From<i32> for LiteralId {
    fn from(v: i32) -> Self {
        Self(v as u32)
    }
}

impl From<u32> for LiteralId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<LiteralId> for u32 {
    fn from(v: LiteralId) -> Self {
        v.0
    }
}

impl From<LiteralId> for i64 {
    fn from(v: LiteralId) -> Self {
        v.0 as i64
    }
}

impl From<LiteralId> for u64 {
    fn from(v: LiteralId) -> Self {
        v.0 as u64
    }
}

/// ID associated to each namespace.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct NamespaceId(i32);

/// ID associated to each rule.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) struct RuleId(i32);

impl RuleId {
    /// Returns the [`RuleId`] that comes after this one.
    ///
    /// This simply adds 1 to the ID.
    #[allow(dead_code)]
    pub(crate) fn next(&self) -> Self {
        RuleId(self.0 + 1)
    }
}

impl From<i32> for RuleId {
    #[inline]
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<usize> for RuleId {
    #[inline]
    fn from(value: usize) -> Self {
        Self(value.try_into().unwrap())
    }
}

impl From<RuleId> for usize {
    #[inline]
    fn from(value: RuleId) -> Self {
        value.0 as usize
    }
}

impl From<RuleId> for i32 {
    #[inline]
    fn from(value: RuleId) -> Self {
        value.0
    }
}

/// ID associated to each regexp used in a rule condition.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct RegexpId(i32);

impl From<i32> for RegexpId {
    #[inline]
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<u32> for RegexpId {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value.try_into().unwrap())
    }
}

impl From<i64> for RegexpId {
    #[inline]
    fn from(value: i64) -> Self {
        Self(value.try_into().unwrap())
    }
}

impl From<RegexpId> for usize {
    #[inline]
    fn from(value: RegexpId) -> Self {
        value.0 as usize
    }
}

impl From<RegexpId> for i32 {
    #[inline]
    fn from(value: RegexpId) -> Self {
        value.0
    }
}

impl From<RegexpId> for u32 {
    #[inline]
    fn from(value: RegexpId) -> Self {
        value.0.try_into().unwrap()
    }
}

/// ID associated to each pattern.
///
/// For each unique pattern defined in a set of YARA rules there's a PatternId
/// that identifies it. If two different rules define exactly the same pattern
/// there's a single instance of the pattern and therefore a single PatternId
/// shared by both rules. For example, if one rule defines `$a = "mz"` and
/// another one `$mz = "mz"`, the pattern `"mz"` is shared by the two rules.
///
/// However, in order to be considered the same, the following conditions must
/// be met:
///
/// * Both patterns must have the same modifiers (i.e: `"mz" nocase` is not the
///   same pattern as `"mz"`),
/// * Both patterns must be either non-anchored, or anchored to the same offset.
/// * Both patterns must have the same file size bounds (or no bounds at all).
#[derive(
    Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
#[derive(Ord)]
pub(crate) struct PatternId(i32);

impl PatternId {
    #[inline]
    fn incr(&mut self, amount: usize) {
        self.0 += amount as i32;
    }
}

impl From<i32> for PatternId {
    #[inline]
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<usize> for PatternId {
    #[inline]
    fn from(value: usize) -> Self {
        Self(value as i32)
    }
}

impl From<PatternId> for i32 {
    #[inline]
    fn from(value: PatternId) -> Self {
        value.0
    }
}

impl From<PatternId> for i64 {
    #[inline]
    fn from(value: PatternId) -> Self {
        value.0 as i64
    }
}

impl From<PatternId> for usize {
    #[inline]
    fn from(value: PatternId) -> Self {
        value.0 as usize
    }
}

/// ID associated to each sub-pattern.
///
/// For each pattern there's one or more sub-patterns, depending on the pattern
/// and its modifiers. For example the pattern `"foo" ascii wide` may have one
/// subpattern for the ascii case and another one for the wide case.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SubPatternId(u32);

/// Iterator that yields the names of the modules imported by the rules.
pub struct Imports<'a> {
    iter: std::slice::Iter<'a, IdentId>,
    ident_pool: &'a StringPool<IdentId>,
}

impl<'a> Iterator for Imports<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|id| self.ident_pool.get(*id).unwrap())
    }
}

bitflags! {
    /// Flags associated to some kinds of [`SubPattern`].
    #[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SubPatternFlags: u16  {
        const Wide                 = 0x01;
        const Nocase               = 0x02;
        // Indicates that the pattern is the last one in chain. Applies only
        // to chained sub-patterns.
        const LastInChain          = 0x04;
        const FullwordLeft         = 0x08;
        const FullwordRight        = 0x10;
        // Indicates that the pattern is a greedy regexp. Apply only to regexp
        // sub-patterns, or to any sub-pattern is part of chain that corresponds
        // to a greedy regexp.
        const GreedyRegexp         = 0x20;
        // Indicates that the pattern is a fast regexp. A fast regexp is one
        // that can be matched by the FastVM.
        const FastRegexp           = 0x40;
    }
}

/// A sub-pattern in the compiled rules.
///
/// Each pattern in a rule has one or more associated sub-patterns. For
/// example, the pattern `$a = "foo" ascii wide` has a sub-pattern for the
/// ASCII variant of "foo", and another one for the wide variant.
///
/// Also, each [`Atom`] is associated to a [`SubPattern`]. When the atom is
/// found in the scanned data by the Aho-Corasick algorithm, the scanner
/// verifies that the sub-pattern actually matches.
#[derive(Serialize, Deserialize)]
pub(crate) enum SubPattern {
    Literal {
        pattern: LiteralId,
        anchored_at: Option<usize>,
        flags: SubPatternFlags,
    },

    LiteralChainHead {
        pattern: LiteralId,
        flags: SubPatternFlags,
    },

    LiteralChainTail {
        pattern: LiteralId,
        chained_to: SubPatternId,
        gap: ChainedPatternGap,
        flags: SubPatternFlags,
    },

    Regexp {
        flags: SubPatternFlags,
    },

    RegexpChainHead {
        flags: SubPatternFlags,
    },

    RegexpChainTail {
        chained_to: SubPatternId,
        gap: ChainedPatternGap,
        flags: SubPatternFlags,
    },

    Xor {
        pattern: LiteralId,
        flags: SubPatternFlags,
    },

    Base64 {
        pattern: LiteralId,
        padding: u8,
    },

    Base64Wide {
        pattern: LiteralId,
        padding: u8,
    },

    CustomBase64 {
        pattern: LiteralId,
        alphabet: LiteralId,
        padding: u8,
    },

    CustomBase64Wide {
        pattern: LiteralId,
        alphabet: LiteralId,
        padding: u8,
    },
}

impl SubPattern {
    /// If this sub-pattern is chained to another one, returns the
    /// [`SubPatternId`] associated to this other pattern.
    pub fn chained_to(&self) -> Option<SubPatternId> {
        match self {
            SubPattern::LiteralChainTail { chained_to, .. }
            | SubPattern::RegexpChainTail { chained_to, .. } => {
                Some(*chained_to)
            }
            _ => None,
        }
    }
}

/// A snapshot that represents the state of the compiler at a particular moment.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    next_pattern_id: PatternId,
    rules_len: usize,
    atoms_len: usize,
    re_code_len: usize,
    sub_patterns_len: usize,
    symbol_table_len: usize,
}

/// Represents a list of warnings.
///
/// This is a wrapper around a `Vec<Warning>` that contains additional logic
/// for limiting the number of warnings stored in the vector and silencing some
/// warnings types.
pub(crate) struct Warnings {
    warnings: Vec<Warning>,
    /// Maximum number of warnings that will be stored in `warnings`.
    max_warnings: usize,
    /// Warnings that are globally disabled.
    disabled_warnings: HashSet<String>,
    /// Warnings that are suppressed for a specific code span. Keys are
    /// warning identifiers, and values are the code spans in which the
    /// warning is disabled.
    suppressed_warnings: HashMap<String, Vec<Span>>,
}

impl Default for Warnings {
    fn default() -> Self {
        Self {
            warnings: Vec::new(),
            max_warnings: 100,
            disabled_warnings: HashSet::default(),
            suppressed_warnings: HashMap::default(),
        }
    }
}

impl Warnings {
    /// Adds the warning returned by `f` to the list.
    ///
    /// If the maximum number of warnings has been reached the warning is not
    /// added.
    #[inline]
    pub fn add(&mut self, f: impl FnOnce() -> Warning) {
        if self.warnings.len() < self.max_warnings {
            let warning = f();
            let mut warn = !self.disabled_warnings.contains(warning.code());

            if warn {
                if let Some(spans) =
                    self.suppressed_warnings.get(warning.code())
                {
                    'l: for disabled_span in spans {
                        for label in warning.labels() {
                            if disabled_span.contains(label.span()) {
                                warn = false;
                                break 'l;
                            }
                        }
                    }
                }
            }

            if warn {
                self.warnings.push(warning);
            }
        }
    }

    /// Returns true if the given code is a valid warning code.
    pub fn is_valid_code(code: &str) -> bool {
        Warning::all_codes().contains(&code)
    }

    /// Enables or disables a specific warning identified by `code`.
    ///
    /// Returns `true` if the warning was previously enabled, or `false` if
    /// otherwise. Returns an error if the code doesn't correspond to any
    /// of the existing warnings.
    #[inline]
    pub fn switch_warning(
        &mut self,
        code: &str,
        enabled: bool,
    ) -> Result<bool, InvalidWarningCode> {
        if !Self::is_valid_code(code) {
            return Err(InvalidWarningCode::new(code.to_string()));
        }
        if enabled {
            Ok(!self.disabled_warnings.remove(code))
        } else {
            Ok(self.disabled_warnings.insert(code.to_string()))
        }
    }

    /// Enable or disables all warnings.
    pub fn switch_all_warnings(&mut self, enabled: bool) {
        if enabled {
            self.disabled_warnings.clear();
        } else {
            for c in Warning::all_codes() {
                self.disabled_warnings.insert(c.to_string());
            }
        }
    }

    /// Clear suppressed warnings.
    pub fn clear_suppressed(&mut self) {
        self.suppressed_warnings.clear();
    }

    /// Suppress the warning with the given code, for the given span.
    pub fn suppress(&mut self, code: &str, span: Span) {
        self.suppressed_warnings
            .entry(code.to_string())
            .or_default()
            .push(span);
    }

    #[inline]
    pub fn as_slice(&self) -> &[Warning] {
        self.warnings.as_slice()
    }
}

impl From<Warnings> for Vec<Warning> {
    fn from(value: Warnings) -> Self {
        value.warnings
    }
}
