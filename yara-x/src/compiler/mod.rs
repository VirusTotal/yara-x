/*! Compiles YARA source code into binary form.

YARA rules must be compiled before they can be used for scanning data. This
module implements the YARA compiler.
*/

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::path::Path;
use std::rc::Rc;
use std::{fmt, iter, u32};

use aho_corasick::AhoCorasick;
use bincode::Options;
use bitmask::bitmask;
use bstr::ByteSlice;
use itertools::Itertools;
use regex_syntax::hir;
use regex_syntax::hir::Literal;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use walrus::FunctionId;

use yara_x_parser::ast;
use yara_x_parser::ast::{HasSpan, Ident, RuleFlag};
use yara_x_parser::report::ReportBuilder;
use yara_x_parser::warnings::Warning;
use yara_x_parser::{Parser, SourceCode};

use crate::compiler::atoms::base64::base64_patterns;
use crate::compiler::emit::emit_rule_condition;
use crate::compiler::{Context, VarStack};
use crate::modules::BUILTIN_MODULES;
use crate::string_pool::{BStringPool, StringPool};
use crate::symbols::{
    StackedSymbolTable, Symbol, SymbolKind, SymbolLookup, SymbolTable,
};
use crate::types::{Func, FuncSignature, Struct, TypeValue, Value};
use crate::utils::cast;
use crate::variables::{is_valid_identifier, Variable, VariableError};
use crate::wasm::builder::WasmModuleBuilder;
use crate::wasm::{WasmSymbols, WASM_EXPORTS};

pub(crate) use crate::compiler::atoms::*;
pub(crate) use crate::compiler::context::*;
pub(crate) use crate::compiler::ir::*;

#[doc(inline)]
pub use crate::compiler::errors::*;

#[doc(inline)]
pub use crate::compiler::rules::*;
use crate::compiler::SubPattern::{Regexp, RegexpChainHead, RegexpChainTail};
use crate::re;
use crate::re::hir::TrailingPattern;

mod atoms;
mod context;
mod emit;
mod errors;
mod ir;
mod rules;

#[cfg(test)]
mod tests;

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
/// let results = scanner.scan("Lorem ipsum".as_bytes());
/// assert_eq!(results.matching_rules().len(), 1);
/// ```
pub fn compile<'src, S>(src: S) -> Result<Rules, Error>
where
    S: Into<SourceCode<'src>>,
{
    Ok(Compiler::new().add_source(src)?.build())
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
/// let rules = yara_x::Compiler::new()
///     .add_source(r#"
///         rule always_true {
///             condition: true
///         }"#)?
///     .add_source(r#"
///         rule always_false {
///             condition: false
///         }"#)?
///     .build();
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
pub struct Compiler<'a> {
    /// Used for generating error and warning reports.
    report_builder: ReportBuilder,

    /// The main symbol table used by the compiler. This is actually a stack of
    /// symbol tables where the bottom-most table is the one that contains
    /// global identifiers like built-in functions and user-defined global
    /// identifiers.
    symbol_table: StackedSymbolTable<'a>,

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
    /// identifier `$a`. Each identifier have an unique 32-bits [`IdentId`]
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

    /// A vector with all the rules that has been compiled. A [`RuleId`] is
    /// an index in this vector.
    rules: Vec<RuleInfo>,

    /// Next (not used yet) [`PatternId`].
    next_pattern_id: i32,

    /// A vector with all the sub-patterns from all the rules. A
    /// [`SubPatternId`] is an index in this vector.
    sub_patterns: Vec<(PatternId, SubPattern)>,

    /// A vector that contains all the atoms generated for literal patterns.
    /// Each atom has an associated [`SubPatternId`] that indicates the
    /// sub-pattern it belongs to.
    atoms: Vec<SubPatternAtom>,

    /// A vector that contains the code for all regexp patterns (this includes
    /// hex patterns which are just an special case of regexp). The code for
    /// each regexp is appended to the vector, during the compilation process
    /// and the atoms extracted from the regexp contain offsets within this
    /// vector. This vector contains both forward and backward code.
    re_code: Vec<u8>,

    /// Vector with the names of all the imported modules. The vector contains
    /// the [`IdentId`] corresponding to the module's identifier.
    imported_modules: Vec<IdentId>,

    /// Structure where each field corresponds to a module imported by the
    /// rules. The value of each field is the structure that describes the
    /// module.
    modules_struct: Struct,

    /// Structure where each field corresponds to some global identifier.
    globals_struct: Struct,

    /// Warnings generated while compiling the rules.
    warnings: Vec<Warning>,
}

impl<'a> Compiler<'a> {
    /// Creates a new YARA compiler.
    pub fn new() -> Self {
        let mut ident_pool = StringPool::new();
        let mut symbol_table = StackedSymbolTable::new();

        // Add symbols for built-in functions like uint8, uint16, etc.
        let global_symbols = symbol_table.push_new();

        for export in WASM_EXPORTS.iter().filter(|e| e.public) {
            let func = Rc::new(Func::with_signature(FuncSignature::from(
                export.mangled_name.to_string(),
            )));

            let symbol = Symbol::new(
                TypeValue::Func(func.clone()),
                SymbolKind::Func(func),
            );

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
        let wasm_mod = WasmModuleBuilder::new();

        let wasm_symbols = wasm_mod.wasm_symbols();
        let wasm_exports = wasm_mod.wasm_exports();

        Self {
            ident_pool,
            global_symbols,
            symbol_table,
            wasm_mod,
            wasm_symbols,
            wasm_exports,
            next_pattern_id: 0,
            current_namespace: default_namespace,
            warnings: Vec::new(),
            rules: Vec::new(),
            sub_patterns: Vec::new(),
            atoms: Vec::new(),
            re_code: Vec::new(),
            imported_modules: Vec::new(),
            modules_struct: Struct::new(),
            globals_struct: Struct::new(),
            report_builder: ReportBuilder::new(),
            lit_pool: BStringPool::new(),
            regexp_pool: StringPool::new(),
        }
    }

    /// Adds a YARA source code to be compiled.
    ///
    /// This function can be called multiple times.
    pub fn add_source<'src, S>(mut self, src: S) -> Result<Self, Error>
    where
        S: Into<SourceCode<'src>>,
    {
        // Convert `src` into an instance of `SourceCode` if it is something
        // else, like a &str.
        let src = src.into();

        // Parse the source code and build the Abstract Syntax Tree.
        let mut ast = Parser::new()
            .set_report_builder(&self.report_builder)
            .build_ast(src)?;

        // Process import statements. Checks that all imported modules
        // actually exist, and raise warnings in case of duplicated
        // imports within the same source file. For each module add a
        // symbol to the current namespace.
        self.process_imports(&ast.imports)?;

        // Iterate over the list of declared rules and verify that their
        // conditions are semantically valid. For each rule add a symbol
        // to the current namespace.
        for rule in &ast.rules {
            self.process_rule(rule)?;
        }

        // Transfer the warnings generated by the parser to the compiler
        self.warnings.append(&mut ast.warnings);

        Ok(self)
    }

    /// Defines a global variable and sets its initial value.
    ///
    /// `T` can be any type that implements [`Into<Variable>`], which includes:
    /// `i64`, `i32`, `i16`, `i8`, `u32`, `u16`, `u8`, `f64`, `f32`, `bool`,
    /// `&str` and `String`.
    ///
    /// Global variables must be defined before calling [`Compiler::add_source`]
    /// with some YARA rule that uses the variable. The variable will retain its
    /// initial value when the [`Rules`] are used for scanning data, however
    /// each scanner can change the variable's value by calling
    /// [`crate::Scanner::set_global`].
    pub fn define_global<T: Into<Variable>>(
        mut self,
        ident: &str,
        value: T,
    ) -> Result<Self, VariableError> {
        if !is_valid_identifier(ident) {
            return Err(VariableError::InvalidIdentifier(ident.to_string()));
        }

        let var: Variable = value.into();
        let type_value: TypeValue = var.into();

        if self.globals_struct.add_field(ident, type_value.clone()).is_some() {
            return Err(VariableError::AlreadyExists(ident.to_string()));
        }

        self.global_symbols.borrow_mut().insert(
            ident,
            Symbol::new(
                type_value,
                SymbolKind::FieldIndex(self.globals_struct.index_of(ident)),
            ),
        );

        Ok(self)
    }

    /// Creates a new namespace.
    ///
    /// Further calls to [`Compiler::add_source`] will put the rules under the
    /// newly created namespace.
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
    /// `foo` is not visible to `bar`, and the second all to `add_source`
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
    pub fn new_namespace(mut self, namespace: &str) -> Self {
        // Remove the symbol table corresponding to the previous namespace.
        self.symbol_table.pop().expect("expecting a namespace");
        // Create a new namespace. The NamespaceId is simply the ID of the
        // previous namespace + 1.
        self.current_namespace = Namespace {
            id: NamespaceId(self.current_namespace.id.0 + 1),
            ident_id: self.ident_pool.get_or_intern(namespace),
            symbols: self.symbol_table.push_new(),
        };
        self.wasm_mod.new_namespace();
        self
    }

    /// Returns the warnings produced while compiling the rules.
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Builds the source code previously added to the compiler.
    ///
    /// This function consumes the compiler and returns an instance of
    /// [`Rules`].
    pub fn build(self) -> Rules {
        // Finish building the WASM module.
        let wasm_mod = self.wasm_mod.build().emit_wasm();

        // Compile the WASM module for the current platform. This panics
        // if the WASM code is invalid, which should not happen as the code is
        // emitted by YARA itself. If this ever happens is probably because
        // wrong WASM code is being emitted.
        let compiled_wasm_mod = wasmtime::Module::from_binary(
            &crate::wasm::ENGINE,
            wasm_mod.as_slice(),
        )
        .expect("WASM module is not valid");

        // Build the Aho-Corasick automaton used while searching for the atoms
        // in the scanned data.
        let ac = AhoCorasick::new(self.atoms.iter().map(|a| a.as_slice()))
            .expect("failed to build Aho-Corasick automaton");

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
        let serialized_globals = bincode::DefaultOptions::new()
            .serialize(&self.globals_struct)
            .expect("failed to serialize global variables");

        Rules {
            serialized_globals,
            wasm_mod: compiled_wasm_mod,
            ac: Some(ac),
            num_patterns: self.next_pattern_id as usize,
            ident_pool: self.ident_pool,
            regexp_pool: self.regexp_pool,
            lit_pool: self.lit_pool,
            imported_modules: self.imported_modules,
            rules: self.rules,
            sub_patterns: self.sub_patterns,
            atoms: self.atoms,
            re_code: self.re_code,
        }
    }

    /// Specifies whether the compiler should produce colorful error messages.
    ///
    /// Colorized error messages contain ANSI escape sequences that make them
    /// look nicer on compatible consoles. The default setting is `false`.
    pub fn colorize_errors(mut self, b: bool) -> Self {
        self.report_builder.with_colors(b);
        self
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
}

impl<'a> Compiler<'a> {
    /// Check if another rule, module or variable has the given identifier and
    /// return an error in that case.
    fn check_for_existing_identifier(
        &self,
        ident: &Ident,
    ) -> Result<(), CompileError> {
        if let Some(symbol) = self.symbol_table.lookup(ident.name) {
            return match symbol.kind() {
                SymbolKind::Rule(rule_id) => {
                    Err(CompileError::from(CompileErrorInfo::duplicate_rule(
                        &self.report_builder,
                        ident.name.to_string(),
                        ident.span,
                        self.rules.get(rule_id.0 as usize).unwrap().ident_span,
                    )))
                }
                _ => Err(CompileError::from(
                    CompileErrorInfo::conflicting_rule_identifier(
                        &self.report_builder,
                        ident.name.to_string(),
                        ident.span,
                    ),
                )),
            };
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

    fn process_rule(&mut self, rule: &ast::Rule) -> Result<(), CompileError> {
        // Check if another rule, module or variable has the same identifier
        // and return an error in that case.
        self.check_for_existing_identifier(&rule.identifier)?;

        // Convert the patterns from AST to IR.
        let patterns = ir::patterns_from_ast(
            &self.report_builder,
            rule.patterns.as_ref(),
        )?;

        // Create array with pairs (IdentId, PatternId) that describe
        // the patterns in a compiled rule.
        let mut ident_and_pattern = Vec::with_capacity(patterns.len());

        for pattern in patterns.into_iter() {
            // Save pattern identifier (e.g: $a) in the pool of identifiers
            // or reuse the IdentId if the identifier has been used already.
            let ident_id = self.ident_pool.get_or_intern(pattern.identifier());

            match pattern {
                ir::Pattern::Literal(pattern) => {
                    self.process_literal_pattern(pattern);
                }
                ir::Pattern::Regexp(pattern) => {
                    self.process_regexp_pattern(pattern);
                }
            };

            // Add the pair (IdentId, PatternId).
            ident_and_pattern
                .push((ident_id, PatternId(self.next_pattern_id)));

            self.next_pattern_id += 1;
        }

        let rule_id = RuleId(self.rules.len() as i32);

        self.rules.push(RuleInfo {
            namespace_id: self.current_namespace.id,
            namespace_ident_id: self.current_namespace.ident_id,
            ident_id: self.ident_pool.get_or_intern(rule.identifier.name),
            ident_span: rule.identifier.span,
            patterns: ident_and_pattern,
            is_global: rule.flags.contains(RuleFlag::Global),
        });

        // Create a new symbol of bool type for the rule.
        let new_symbol = Symbol::new(
            TypeValue::Bool(Value::Unknown),
            SymbolKind::Rule(rule_id),
        );

        // Insert the symbol in the symbol table corresponding to the
        // current namespace.
        let existing_symbol = self
            .current_namespace
            .symbols
            .as_ref()
            .borrow_mut()
            .insert(rule.identifier.name, new_symbol);

        // No other symbol with the same identifier should exist.
        assert!(existing_symbol.is_none());

        let mut ctx = Context {
            current_struct: None,
            current_signature: None,
            symbol_table: &mut self.symbol_table,
            ident_pool: &mut self.ident_pool,
            lit_pool: &mut self.lit_pool,
            regexp_pool: &mut self.regexp_pool,
            report_builder: &self.report_builder,
            rules: &self.rules,
            current_rule: self.rules.last().unwrap(),
            wasm_symbols: &self.wasm_symbols,
            wasm_exports: &self.wasm_exports,
            warnings: &mut self.warnings,
            exception_handler_stack: Vec::new(),
            lookup_start: None,
            lookup_stack: VecDeque::new(),
            vars: VarStack::new(),
        };

        let mut condition = ir::expr_from_ast(&mut ctx, &rule.condition)?;

        ir::warn_if_not_bool(&mut ctx, condition.ty(), rule.condition.span());

        emit_rule_condition(
            &mut ctx,
            &mut self.wasm_mod,
            rule_id,
            rule.flags,
            &mut condition,
        );

        // After emitting the whole condition, the stack of variables should
        // be empty.
        assert_eq!(ctx.vars.used, 0);

        Ok(())
    }

    fn process_literal_pattern(&mut self, pattern: ir::LiteralPattern) {
        let full_word = pattern.flags.contains(PatternFlags::Fullword);
        let mut flags = SubPatternFlagSet::none();

        if full_word {
            flags.set(SubPatternFlags::FullwordLeft);
            flags.set(SubPatternFlags::FullwordRight);
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
                best_atom_from_slice(
                    wide_pattern.as_slice(),
                    // For wide patterns let's use atoms twice large as usual.
                    DESIRED_ATOM_SIZE * 2,
                ),
                flags | SubPatternFlags::Wide,
            ));
        }

        if pattern.flags.contains(PatternFlags::Ascii) {
            main_patterns.push((
                pattern.text.as_bytes(),
                best_atom_from_slice(
                    pattern.text.as_bytes(),
                    DESIRED_ATOM_SIZE,
                ),
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

                self.add_sub_pattern(
                    SubPattern::Xor { pattern: pattern_lit_id, flags },
                    XorGenerator::new(
                        best_atom,
                        pattern.xor_range.clone().unwrap(),
                    ),
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
                    SubPattern::Literal {
                        pattern: pattern_lit_id,
                        flags: flags | SubPatternFlags::Nocase,
                    },
                    CaseGenerator::new(&best_atom),
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
                    for (padding, base64_pattern) in
                        base64_patterns(main_pattern, pattern.base64_alphabet)
                    {
                        let sub_pattern =
                            if let Some(alphabet) = pattern.base64_alphabet {
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
                            sub_pattern,
                            iter::once(
                                best_atom_from_slice(
                                    base64_pattern.as_slice(),
                                    DESIRED_ATOM_SIZE,
                                )
                                // Atoms for base64 patterns are always
                                // inexact, they require verification.
                                .make_inexact(),
                            ),
                            SubPatternAtom::from_atom,
                        );
                    }
                }

                if pattern.flags.contains(PatternFlags::Base64Wide) {
                    for (padding, base64_pattern) in base64_patterns(
                        main_pattern,
                        pattern.base64wide_alphabet,
                    ) {
                        let sub_pattern = if let Some(alphabet) =
                            pattern.base64wide_alphabet
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
                            sub_pattern,
                            iter::once(
                                best_atom_from_slice(
                                    wide.as_slice(),
                                    DESIRED_ATOM_SIZE * 2,
                                )
                                // Atoms for base64 patterns are always
                                // inexact, they require verification.
                                .make_inexact(),
                            ),
                            SubPatternAtom::from_atom,
                        );
                    }
                }
            } else {
                self.add_sub_pattern(
                    SubPattern::Literal { pattern: pattern_lit_id, flags },
                    iter::once(best_atom),
                    SubPatternAtom::from_atom,
                );
            }
        }
    }

    fn process_regexp_pattern(&mut self, pattern: ir::RegexpPattern) {
        let ascii = pattern.flags.contains(PatternFlags::Ascii);
        let wide = pattern.flags.contains(PatternFlags::Wide);
        let case_insensitive = pattern.flags.contains(PatternFlags::Nocase);
        let full_word = pattern.flags.contains(PatternFlags::Fullword);

        let mut flags = SubPatternFlagSet::none();

        if case_insensitive {
            flags.set(SubPatternFlags::Nocase);
        }

        if full_word {
            flags.set(SubPatternFlags::FullwordLeft);
            flags.set(SubPatternFlags::FullwordRight);
        }

        // Try splitting the regexp into multiple chained sub-patterns if it
        // contains large gaps. If the regexp can't be split the leading part
        // is the whole regexp.
        let (leading, trailing) = pattern.hir.split_at_large_gaps();

        if trailing.is_empty() && leading.is_alternation_literal() {
            // The pattern is either a literal, or an alternation of literals,
            // examples:
            //      /foo/                       literal
            //      /foo|bar|baz/               alternation of literals
            //      { 01 02 03 }                literal
            //      { (01 02 03 | 04 05 06 )}   alternation of literals
            let mut process_literal = |literal: &hir::Literal, wide: bool| {
                let pattern_lit_id =
                    self.intern_literal(literal.0.as_bytes(), wide);

                let best_atom = best_atom_from_slice(
                    self.lit_pool.get_bytes(pattern_lit_id).unwrap(),
                    if wide {
                        DESIRED_ATOM_SIZE * 2
                    } else {
                        DESIRED_ATOM_SIZE
                    },
                );

                let sp = SubPattern::Literal {
                    pattern: pattern_lit_id,
                    flags: if wide {
                        flags | SubPatternFlags::Wide
                    } else {
                        flags
                    },
                };

                if case_insensitive {
                    self.add_sub_pattern(
                        sp,
                        CaseGenerator::new(&best_atom),
                        SubPatternAtom::from_atom,
                    );
                } else {
                    self.add_sub_pattern(
                        sp,
                        iter::once(best_atom),
                        SubPatternAtom::from_atom,
                    );
                }
            };

            match leading.into_kind() {
                hir::HirKind::Literal(literal) => {
                    if ascii {
                        process_literal(&literal, false);
                    }
                    if wide {
                        process_literal(&literal, true);
                    }
                }
                hir::HirKind::Alternation(literals) => {
                    let literals = literals.into_iter().map({
                        |l| cast!(l.into_kind(), hir::HirKind::Literal)
                    });
                    for literal in literals {
                        if ascii {
                            process_literal(&literal, false);
                        }
                        if wide {
                            process_literal(&literal, true);
                        }
                    }
                }
                _ => unreachable!(),
            }
        } else if trailing.is_empty() {
            if matches!(leading.is_greedy(), Some(true)) {
                flags.set(SubPatternFlags::Greedy);
            }

            // The pattern is a regexp that can't be converted into a literal
            // or alternation of literals, and can't be split into multiple
            // regexps.
            let atoms = self.compile_regexp(&leading);

            if wide {
                self.add_sub_pattern(
                    Regexp { flags: flags | SubPatternFlags::Wide },
                    atoms.iter(),
                    SubPatternAtom::from_regexp_atom_wide,
                );
            }

            if ascii {
                self.add_sub_pattern(
                    Regexp { flags },
                    atoms.into_iter(),
                    SubPatternAtom::from_regexp_atom,
                );
            }
        } else {
            // The pattern is a regexp that was split into multiple chained
            // regexps.
            self.process_chain(&leading, &trailing, pattern.flags);
        }
    }

    fn process_chain(
        &mut self,
        leading: &re::hir::Hir,
        trailing: &[TrailingPattern],
        flags: PatternFlagSet,
    ) {
        let ascii = flags.contains(PatternFlags::Ascii);
        let wide = flags.contains(PatternFlags::Wide);
        let case_insensitive = flags.contains(PatternFlags::Nocase);
        let full_word = flags.contains(PatternFlags::Fullword);

        let mut flags = SubPatternFlagSet::none();

        if case_insensitive {
            flags.set(SubPatternFlags::Nocase);
        }

        if full_word {
            flags.set(SubPatternFlags::FullwordLeft);
        }

        let mut prev_sub_pattern_ascii = SubPatternId(0);
        let mut prev_sub_pattern_wide = SubPatternId(0);

        if let hir::HirKind::Literal(literal) = leading.kind() {
            if ascii {
                prev_sub_pattern_ascii =
                    self.process_literal_chain_head(literal, flags);
            }
            if wide {
                prev_sub_pattern_wide = self.process_literal_chain_head(
                    literal,
                    flags | SubPatternFlags::Wide,
                );
            };
        } else {
            if matches!(leading.is_greedy(), Some(true)) {
                flags.set(SubPatternFlags::Greedy);
            }

            let atoms = self.compile_regexp(leading);

            if wide {
                prev_sub_pattern_wide = self.add_sub_pattern(
                    RegexpChainHead { flags: flags | SubPatternFlags::Wide },
                    atoms.iter(),
                    SubPatternAtom::from_regexp_atom_wide,
                );
            }

            if ascii {
                prev_sub_pattern_ascii = self.add_sub_pattern(
                    RegexpChainHead { flags },
                    atoms.into_iter(),
                    SubPatternAtom::from_regexp_atom,
                );
            }
        }

        // The head of the chain is the only one that has the `FullwordLeft`
        // flag, now that the head has been processed we must unset this flag.
        if full_word {
            flags.unset(SubPatternFlags::FullwordLeft);
        }

        for (i, p) in trailing.iter().enumerate() {
            // The last pattern in the chain has the `LastInChain` flag and
            // the `FullwordRight` if the original pattern was `Fullword`.
            // Patterns in the middle of the chain won't have neither of these
            // flags.
            if i == trailing.len() - 1 {
                flags.set(SubPatternFlags::LastInChain);
                if full_word {
                    flags.set(SubPatternFlags::FullwordRight);
                }
            }

            if let hir::HirKind::Literal(literal) = p.hir.kind() {
                if wide {
                    prev_sub_pattern_wide = self.process_literal_chain_tail(
                        literal,
                        prev_sub_pattern_wide,
                        p.gap.clone(),
                        flags | SubPatternFlags::Wide,
                    );
                };
                if ascii {
                    prev_sub_pattern_ascii = self.process_literal_chain_tail(
                        literal,
                        prev_sub_pattern_ascii,
                        p.gap.clone(),
                        flags,
                    );
                }
            } else {
                if matches!(p.hir.is_greedy(), Some(true)) {
                    flags.set(SubPatternFlags::Greedy);
                }

                let atoms = self.compile_regexp(&p.hir);

                if wide {
                    prev_sub_pattern_wide = self.add_sub_pattern(
                        RegexpChainTail {
                            chained_to: prev_sub_pattern_wide,
                            gap: p.gap.clone(),
                            flags: flags | SubPatternFlags::Wide,
                        },
                        atoms.iter(),
                        SubPatternAtom::from_regexp_atom_wide,
                    )
                }

                if ascii {
                    prev_sub_pattern_ascii = self.add_sub_pattern(
                        RegexpChainTail {
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
    }

    fn compile_regexp(
        &mut self,
        hir: &re::hir::Hir,
    ) -> Vec<re::compiler::RegexpAtom> {
        let re_compiler = re::compiler::Compiler::new();
        let (forward_code, backward_code, mut atoms) =
            re_compiler.compile(hir);

        // `fwd_code` will contain the offset within the `re_code` vector
        // where the forward code resides.
        let fwd_code = self.re_code.len();
        self.re_code.append(&mut forward_code.into_inner());

        // `bck_code` will contain the offset within the `re_code` vector
        // where the backward code resides.
        let bck_code = self.re_code.len();
        self.re_code.append(&mut backward_code.into_inner());

        // The forward and backward code locations in each atom are relative
        // to the start of the code generated for this regexp. Here we make
        // them relative to the start of `re_code`.
        for atom in atoms.iter_mut() {
            atom.code_loc.fwd += fwd_code;
            atom.code_loc.bck += bck_code;
        }

        atoms
    }

    fn process_literal_chain_head(
        &mut self,
        literal: &Literal,
        flags: SubPatternFlagSet,
    ) -> SubPatternId {
        let pattern_lit_id = self.intern_literal(
            literal.0.as_bytes(),
            flags.contains(SubPatternFlags::Wide),
        );
        self.add_sub_pattern(
            SubPattern::LiteralChainHead { pattern: pattern_lit_id, flags },
            extract_atoms(
                self.lit_pool.get_bytes(pattern_lit_id).unwrap(),
                flags,
            ),
            SubPatternAtom::from_atom,
        )
    }

    fn process_literal_chain_tail(
        &mut self,
        literal: &Literal,
        chained_to: SubPatternId,
        gap: RangeInclusive<u32>,
        flags: SubPatternFlagSet,
    ) -> SubPatternId {
        let pattern_lit_id = self.intern_literal(
            literal.0.as_bytes(),
            flags.contains(SubPatternFlags::Wide),
        );
        self.add_sub_pattern(
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

    fn process_imports(
        &mut self,
        imports: &[ast::Import],
    ) -> Result<(), CompileError> {
        // Remove duplicate imports. Duplicate imports raise a warning, but
        // they are allowed for backward-compatibility. We don't want to
        // process the same import twice.
        let imports = imports.iter().unique_by(|m| &m.module_name);

        // Iterate over the list of imported modules.
        for import in imports {
            let module = BUILTIN_MODULES.get(import.module_name.as_str());

            // Does the imported module actually exist? ...
            if module.is_none() {
                // The module does not exist, that's an error.
                return Err(CompileError::from(
                    CompileErrorInfo::unknown_module(
                        &self.report_builder,
                        import.module_name.to_string(),
                        import.span(),
                    ),
                ));
            }

            let module = module.unwrap();

            // Yes, the module exists, add it module to the list of imported
            // modules and the symbol table.
            let module_name = import.module_name.as_str();

            self.imported_modules
                .push(self.ident_pool.get_or_intern(module_name));

            // Create the structure that describes the module.
            let mut module_struct = Struct::from_proto_descriptor_and_msg(
                &module.root_struct_descriptor,
                None,
                true,
            );

            // Does the YARA module has an associated Rust module? If
            // yes, search for functions exported by the module.
            if let Some(mod_name) = module.rust_module_name {
                // This map will contain all the functions exported by the
                // YARA module. Keys are the function names, and values
                // are `Func` objects.
                let mut functions: FxHashMap<&'static str, Func> =
                    FxHashMap::default();

                // Iterate over public functions in WASM_EXPORTS looking
                // for those that were exported by the current YARA module.
                // Add them to `functions` map, or update the `Func` object
                // an additional signature if the function is overloaded.
                for export in WASM_EXPORTS.iter().filter(|e| e.public) {
                    if export.rust_module_path.contains(mod_name) {
                        let signature = FuncSignature::from(format!(
                            "{}.{}",
                            module_name, export.mangled_name
                        ));
                        // If the function was already present in the map
                        // is because it has multiple signatures. If that's
                        // the case, add more signatures to the existing
                        // `Func` object.
                        if let Some(function) = functions.get_mut(export.name)
                        {
                            function.add_signature(signature)
                        } else {
                            functions.insert(
                                export.name,
                                Func::with_signature(signature),
                            );
                        }
                    }
                }

                // Insert the functions in the module's struct.
                for (name, export) in functions.drain() {
                    if module_struct
                        .add_field(name, TypeValue::Func(Rc::new(export)))
                        .is_some()
                    {
                        panic!("duplicate function `{}`", name)
                    }
                }
            }

            let module_struct = TypeValue::Struct(Rc::new(module_struct));

            // Insert the module in the struct that contains all imported
            // modules. This struct contains all modules imported, from
            // all namespaces. Panic if the module was already in the struct.
            if self
                .modules_struct
                .add_field(module_name, module_struct.clone())
                .is_some()
            {
                panic!("duplicate module `{}`", module_name)
            }

            // Create a symbol for the module and insert it in the symbol
            // table for this namespace.
            let symbol = Symbol::new(
                module_struct,
                SymbolKind::FieldIndex(
                    self.modules_struct.index_of(module_name),
                ),
            );

            // Insert the symbol in the symbol table for the current
            // namespace.
            self.current_namespace
                .symbols
                .as_ref()
                .borrow_mut()
                .insert(module_name, symbol);
        }

        Ok(())
    }

    fn add_sub_pattern<I, F, A>(
        &mut self,
        sub_pattern: SubPattern,
        atoms: I,
        f: F,
    ) -> SubPatternId
    where
        I: Iterator<Item = A>,
        F: Fn(SubPatternId, A) -> SubPatternAtom,
    {
        let sub_pattern_id = SubPatternId(self.sub_patterns.len() as u32);
        self.sub_patterns.push((PatternId(self.next_pattern_id), sub_pattern));

        for atom in atoms.into_iter() {
            self.atoms.push(f(sub_pattern_id, atom))
        }

        sub_pattern_id
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
#[derive(Copy, Clone, Debug)]
pub(crate) struct RuleId(i32);

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

/// ID associated to each regexp used in a rule condition.
#[derive(Copy, Clone, Debug)]
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
/// shared by both rules. Two patterns are considered equal when the have the
/// same data and modifiers, but the identifier is not relevant. For example,
/// if one rule defines `$a = "mz"` and another one `$mz = "mz"`, the pattern
/// `"mz"` is shared by the two rules. Each rule has a Vec<(IdentId, PatternId)>
/// that associates identifiers to their corresponding patterns.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct PatternId(i32);

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

bitmask! {
    /// Flags associated to some kinds of [`SubPattern`].
    #[derive(Debug, Serialize, Deserialize)]
    pub mask SubPatternFlagSet: u8 where flags SubPatternFlags  {
        Wide                 = 0x01,
        Nocase               = 0x02,
        LastInChain          = 0x04, // Apply only to chained sub-patterns.
        FullwordLeft         = 0x08,
        FullwordRight        = 0x10,
        Greedy               = 0x20, // Apply only to regexp sub-patterns.
    }
}

impl SubPatternFlagSet {
    pub(crate) fn fullword(&self) -> bool {
        self.intersects(
            SubPatternFlags::FullwordLeft | SubPatternFlags::FullwordRight,
        )
    }
}

/// A sub-pattern in the compiled rules.
///
/// Each pattern in a rule has one ore more associated sub-patterns. For
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
        flags: SubPatternFlagSet,
    },

    LiteralChainHead {
        pattern: LiteralId,
        flags: SubPatternFlagSet,
    },

    LiteralChainTail {
        pattern: LiteralId,
        chained_to: SubPatternId,
        gap: RangeInclusive<u32>,
        flags: SubPatternFlagSet,
    },

    Regexp {
        flags: SubPatternFlagSet,
    },

    RegexpChainHead {
        flags: SubPatternFlagSet,
    },

    RegexpChainTail {
        chained_to: SubPatternId,
        gap: RangeInclusive<u32>,
        flags: SubPatternFlagSet,
    },

    Xor {
        pattern: LiteralId,
        flags: SubPatternFlagSet,
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
