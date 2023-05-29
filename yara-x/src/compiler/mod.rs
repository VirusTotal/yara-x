/*! Compiles YARA source code into binary form.

YARA rules must be compiled before they can be used for scanning data. This
module implements the YARA compiler.
*/

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::io::{BufWriter, Write};
use std::mem::size_of;
use std::path::Path;
use std::rc::Rc;

use aho_corasick::AhoCorasick;
use bincode::Options;
use bstr::ByteSlice;
use itertools::Itertools;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use walrus::ir::InstrSeqId;
use walrus::{FunctionId, ValType};

use yara_x_parser::ast;
use yara_x_parser::ast::{HasSpan, RuleFlag, Span};
use yara_x_parser::report::ReportBuilder;
use yara_x_parser::warnings::Warning;
use yara_x_parser::{Parser, SourceCode};

use crate::compiler::atoms::base64::base64_patterns;
use crate::compiler::atoms::{
    best_atom_from_slice, make_wide, Atom, CaseGenerator, XorGenerator,
    DESIRED_ATOM_SIZE,
};
use crate::compiler::emit::emit_rule_condition;
use crate::string_pool::{BStringPool, StringPool};
use crate::symbols::{
    StackedSymbolTable, Symbol, SymbolKind, SymbolLookup, SymbolTable,
};
use crate::types::{Func, FuncSignature, Struct, Type, TypeValue};
use crate::variables::{is_valid_identifier, Variable, VariableError};
use crate::wasm;
use crate::wasm::builder::WasmModuleBuilder;
use crate::wasm::{WasmSymbols, WASM_EXPORTS};

#[doc(inline)]
pub use crate::compiler::errors::*;
use crate::compiler::ir::PatternFlags;

use crate::modules::BUILTIN_MODULES;

mod atoms;
mod emit;
mod errors;
mod ir;

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

    /// A vector that contains all the atoms generated for the patterns. Each
    /// atom has an associated [`PatternId`] that indicates the pattern it
    /// belongs to.
    atoms: Vec<AtomInfo>,

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
            imported_modules: Vec::new(),
            modules_struct: Struct::new(),
            globals_struct: Struct::new(),
            report_builder: ReportBuilder::new(),
            lit_pool: BStringPool::new(),
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
        let ac = AhoCorasick::new(self.atoms.iter().map(|x| &x.atom))
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
            wasm_mod,
            serialized_globals,
            ac: Some(ac),
            compiled_wasm_mod: Some(compiled_wasm_mod),
            num_patterns: self.next_pattern_id as usize,
            ident_pool: self.ident_pool,
            lit_pool: self.lit_pool,
            imported_modules: self.imported_modules,
            rules: self.rules,
            sub_patterns: self.sub_patterns,
            atoms: self.atoms,
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
    #[inline]
    fn push_sub_pattern(&mut self, sub_pattern: SubPattern) -> SubPatternId {
        let id = self.sub_patterns.len();
        self.sub_patterns.push((PatternId(self.next_pattern_id), sub_pattern));
        SubPatternId(id as u32)
    }

    fn process_rule(&mut self, rule: &ast::Rule) -> Result<(), CompileError> {
        // Check if another rule, module or variable has the same identifier
        // and return an error in that case.
        if let Some(symbol) = self.symbol_table.lookup(rule.identifier.name) {
            return match symbol.kind() {
                SymbolKind::Rule(rule_id) => {
                    Err(CompileError::from(CompileErrorInfo::duplicate_rule(
                        &self.report_builder,
                        rule.identifier.name.to_string(),
                        rule.identifier.span,
                        self.rules.get(rule_id.0 as usize).unwrap().ident_span,
                    )))
                }
                _ => Err(CompileError::from(
                    CompileErrorInfo::conflicting_rule_identifier(
                        &self.report_builder,
                        rule.identifier.name.to_string(),
                        rule.identifier.span,
                    ),
                )),
            };
        }

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
                ir::Pattern::Text(pattern) => {
                    self.process_text_pattern(pattern);
                }
                ir::Pattern::Hex { .. } => {
                    // TODO
                }
                ir::Pattern::Regexp { .. } => {
                    // TODO
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
        let new_symbol =
            Symbol::new(TypeValue::Bool(None), SymbolKind::Rule(rule_id));

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

    fn process_text_pattern(&mut self, p: ir::TextPattern) {
        // The `ascii` modifier is usually implicit, but when `wide` is used
        // it must be declared explicitly.
        let mut implicit_ascii = true;

        // Depending on the combination of `ascii` and `wide` modifiers, the
        // `main_patterns` vector will contain either the pattern's `ascii`
        // version, the `wide` version, or both. Each item in `main_patterns`
        // also contains the best atom for the pattern.
        let mut main_patterns = Vec::new();
        let wide_pattern;

        if p.flags.contains(PatternFlags::Wide) {
            implicit_ascii = false;
            wide_pattern = make_wide(p.text.as_bytes());
            main_patterns.push((
                true, // is wide
                best_atom_from_slice(
                    wide_pattern.as_slice(),
                    // For wide patterns let's use atoms twice large as usual.
                    DESIRED_ATOM_SIZE * 2,
                ),
                wide_pattern.as_slice(),
            ));
        }

        if implicit_ascii || p.flags.contains(PatternFlags::Ascii) {
            main_patterns.push((
                false, // is not wide
                best_atom_from_slice(p.text.as_bytes(), DESIRED_ATOM_SIZE),
                p.text.as_bytes(),
            ));
        }

        for (wide, best_atom, main_pattern) in main_patterns {
            let full_word =
                match (p.flags.contains(PatternFlags::Fullword), wide) {
                    // fullword and wide
                    (true, true) => FullWord::Wide,
                    // fullword but not wide
                    (true, false) => FullWord::Ascii,
                    // no fullword
                    _ => FullWord::Disabled,
                };

            if p.flags.contains(PatternFlags::Xor) {
                // When `xor` is used, `base64`, `base64wide` and `nocase` are
                // not accepted.
                debug_assert!(!p.flags.contains(
                    PatternFlags::Base64
                        | PatternFlags::Base64Wide
                        | PatternFlags::Nocase,
                ));

                let pattern_lit_id = self.lit_pool.get_or_intern(main_pattern);
                let sub_pattern_id = self.push_sub_pattern(SubPattern::Xor {
                    pattern: pattern_lit_id,
                    full_word,
                });

                let xor_range = p.xor_range.clone().unwrap();

                self.atoms.reserve(xor_range.len());

                for atom in XorGenerator::new(best_atom, xor_range) {
                    self.atoms.push(AtomInfo { sub_pattern_id, atom });
                }
            } else if p.flags.contains(PatternFlags::Nocase) {
                // When `nocase` is used, `base64`, `base64wide` and `xor` are
                // not accepted.
                debug_assert!(!p.flags.contains(
                    PatternFlags::Base64
                        | PatternFlags::Base64Wide
                        | PatternFlags::Xor,
                ));

                let pattern_lit_id = self.lit_pool.get_or_intern(main_pattern);
                let sub_pattern_id =
                    self.push_sub_pattern(SubPattern::FixedCaseInsensitive {
                        pattern: pattern_lit_id,
                        full_word,
                    });

                for atom in CaseGenerator::new(&best_atom) {
                    self.atoms.push(AtomInfo { sub_pattern_id, atom });
                }
            }
            // Used `base64`, or `base64wide`, or both.
            else if p
                .flags
                .intersects(PatternFlags::Base64 | PatternFlags::Base64Wide)
            {
                // When `base64` or `base64wide` are used, `xor`, `fullword`
                // and `nocase` are not accepted.
                debug_assert!(!p.flags.contains(
                    PatternFlags::Xor
                        | PatternFlags::Fullword
                        | PatternFlags::Nocase,
                ));

                if p.flags.contains(PatternFlags::Base64) {
                    for (padding, base64_pattern) in
                        base64_patterns(main_pattern, p.base64_alphabet)
                    {
                        let sub_pattern =
                            if let Some(alphabet) = p.base64_alphabet {
                                SubPattern::CustomBase64 {
                                    pattern: self
                                        .lit_pool
                                        .get_or_intern(main_pattern),
                                    alphabet: self
                                        .lit_pool
                                        .get_or_intern(alphabet),
                                    padding,
                                }
                            } else {
                                SubPattern::Base64 {
                                    pattern: self
                                        .lit_pool
                                        .get_or_intern(main_pattern),
                                    padding,
                                }
                            };

                        let sub_pattern_id =
                            self.push_sub_pattern(sub_pattern);

                        let atom = best_atom_from_slice(
                            base64_pattern.as_slice(),
                            DESIRED_ATOM_SIZE,
                        );

                        self.atoms.push(AtomInfo { sub_pattern_id, atom })
                    }
                }

                if p.flags.contains(PatternFlags::Base64Wide) {
                    for (padding, base64_pattern) in
                        base64_patterns(main_pattern, p.base64wide_alphabet)
                    {
                        let sub_pattern =
                            if let Some(alphabet) = p.base64wide_alphabet {
                                SubPattern::CustomBase64Wide {
                                    pattern: self
                                        .lit_pool
                                        .get_or_intern(main_pattern),
                                    alphabet: self
                                        .lit_pool
                                        .get_or_intern(alphabet),
                                    padding,
                                }
                            } else {
                                SubPattern::Base64Wide {
                                    pattern: self
                                        .lit_pool
                                        .get_or_intern(main_pattern),
                                    padding,
                                }
                            };

                        let sub_pattern_id =
                            self.push_sub_pattern(sub_pattern);

                        let wide = make_wide(base64_pattern.as_slice());
                        let atom = best_atom_from_slice(
                            wide.as_slice(),
                            DESIRED_ATOM_SIZE * 2,
                        );

                        self.atoms.push(AtomInfo { sub_pattern_id, atom })
                    }
                }
            } else {
                let pattern_lit_id = self.lit_pool.get_or_intern(main_pattern);
                let sub_pattern_id =
                    self.push_sub_pattern(SubPattern::Fixed {
                        pattern: pattern_lit_id,
                        full_word,
                    });

                self.atoms.push(AtomInfo { sub_pattern_id, atom: best_atom })
            }
        }
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
        Self(value as i32)
    }
}

impl From<RuleId> for usize {
    #[inline]
    fn from(value: RuleId) -> Self {
        value.0 as usize
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
#[derive(Eq, Copy, Clone, Debug, Hash, PartialEq, Serialize, Deserialize)]
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
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SubPatternId(u32);

/// Structure that contains information and data structures required during the
/// current compilation process.
struct Context<'a, 'sym> {
    /// Builder for creating error and warning reports.
    report_builder: &'a ReportBuilder,

    /// Symbol table that contains the currently defined identifiers, modules,
    /// functions, etc.
    symbol_table: &'a mut StackedSymbolTable<'sym>,

    /// Symbol table for the currently active structure. When this contains
    /// some value, symbols are looked up in this table and the main symbol
    /// table (i.e: `symbol_table`) is ignored.
    current_struct: Option<Rc<dyn SymbolLookup + 'a>>,

    /// Used during code emitting for tracking the function signature
    /// associated to a function call.
    current_signature: Option<usize>,

    /// Table with all the symbols (functions, variables) used by WASM.
    wasm_symbols: &'a WasmSymbols,

    /// Map where keys are fully qualified and mangled function names, and
    /// values are the function's ID in the WASM module.
    wasm_exports: &'a FxHashMap<String, FunctionId>,

    /// Information about the rules compiled so far.
    rules: &'a Vec<RuleInfo>,

    /// Rule that is being compiled.
    current_rule: &'a RuleInfo,

    /// Warnings generated during the compilation.
    warnings: &'a mut Vec<Warning>,

    /// Pool with identifiers used in the rules.
    ident_pool: &'a mut StringPool<IdentId>,

    /// Pool with literal strings used in the rules.
    lit_pool: &'a mut BStringPool<LiteralId>,

    /// Stack of installed exception handlers for catching undefined values.
    exception_handler_stack: Vec<(ValType, InstrSeqId)>,

    /// Stack of variables. These are local variables used during the
    /// evaluation of rule conditions, for example for storing loop variables.
    vars: VarStack,

    /// The lookup_stack contains a sequence of field IDs that will be used
    /// in the next field lookup operation. See [`emit::emit_lookup_common`]
    /// for details.
    lookup_stack: VecDeque<i32>,

    /// The index of the host-side variable that contains the structure where
    /// the lookup operation will be performed.
    lookup_start: Option<Var>,
}

impl<'a, 'sym> Context<'a, 'sym> {
    /// Given an [`IdentId`] returns the identifier as `&str`.
    ///
    /// # Panics
    ///
    /// Panics if no identifier has the provided [`IdentId`].
    #[inline]
    fn resolve_ident(&self, ident_id: IdentId) -> &str {
        self.ident_pool.get(ident_id).unwrap()
    }

    /// Returns a [`RuleInfo`] given its [`RuleId`].
    ///
    /// # Panics
    ///
    /// If no rule with such [`RuleId`] exists.
    #[inline]
    pub(crate) fn get_rule(&self, rule_id: RuleId) -> &RuleInfo {
        self.rules.get(rule_id.0 as usize).unwrap()
    }

    /// Given a pattern identifier (e.g. `$a`, `#a`, `@a`) search for it in
    /// the current rule and return its [`PatternID`].
    ///
    /// Notice that this function accepts identifiers with any of the valid
    /// prefixes `$`, `#`, `@` and `!`.
    ///
    /// # Panics
    ///
    /// Panics if the current rule does not have the requested pattern.
    fn get_pattern_from_current_rule(&self, ident: &str) -> PatternId {
        // Make sure that identifier starts with `$`, `#`, `@` or `!`.
        debug_assert!("$#@!".contains(
            ident
                .chars()
                .next()
                .expect("identifier must be at least 1 character long")
        ));

        for (ident_id, pattern_id) in &self.current_rule.patterns {
            // Ignore the first character (`$`, `#`, `@` or `!`) while
            // comparing the identifiers.
            if self.resolve_ident(*ident_id)[1..] == ident[1..] {
                return *pattern_id;
            }
        }

        panic!(
            "rule `{}` does not have pattern `{}` ",
            self.resolve_ident(self.current_rule.ident_id),
            ident
        );
    }

    /// Given a function mangled name returns its id.
    ///
    /// # Panics
    ///
    /// If a no function with the given name exists.
    pub fn function_id(&self, fn_mangled_name: &str) -> FunctionId {
        *self.wasm_exports.get(fn_mangled_name).unwrap_or_else(|| {
            panic!("can't find function `{}`", fn_mangled_name)
        })
    }
}

/// Represents a stack of variables.
///
/// The variables stack is composed of frames that are stacked one at the
/// top of another. Each frame can contain one or more variables.
///
/// This stack is stored in WASM main memory, in a memory region that goes
/// from [`wasm::VARS_STACK_START`] to [`wasm::VARS_STACK_END`]. The stack
/// is also mirrored at host-side (with host-side we refer to Rust code
/// called from WASM code), because values like structures, maps, and
/// arrays can't be handled by WASM code directly, and they must be
/// accessible to Rust functions called from WASM. These two stacks (the
/// WASM-side stack and the host-side stack) could be fully independent,
/// but they are mirrored for simplicity. This means that calls to this
/// function reserves space in both stacks at the same time, and therefore
/// their sizes are always the same.
///
/// However, each stack slot is used either by WASM-side code or by
/// host-side code, but not by both. The slots that are used by WASM-side
/// remain with empty values in the host-side stack, while the slots that
/// are used by host-side code remain unused and undefined in WASM
/// memory.
pub(crate) struct VarStack {
    used: i32,
}

impl VarStack {
    /// Creates a stack of variables.
    pub fn new() -> Self {
        Self { used: 0 }
    }

    /// Creates a new stack frame with the given capacity on top of the
    /// existing ones. The returned stack frame can hold the specified
    /// number of variables, but not more.
    ///
    /// Use [`VarStackFrame::new_var`] of allocating individual variables
    /// within a frame.
    pub fn new_frame(&mut self, capacity: i32) -> VarStackFrame {
        let start = self.used;
        self.used += capacity;

        if self.used * size_of::<i64>() as i32
            > wasm::VARS_STACK_END - wasm::VARS_STACK_START
        {
            panic!("variables stack overflow");
        }

        VarStackFrame { start, capacity, used: 0 }
    }

    /// Unwinds the stack freeing all frames that were allocated after the
    /// given one, the given frame inclusive.
    pub fn unwind(&mut self, frame: &VarStackFrame) {
        if self.used < frame.start {
            panic!("double-free in VarStack")
        }
        self.used = frame.start;
    }
}

/// Represents a frame in the stack of variables.
///
/// Frames are stacked one in top of another, individual variables are
/// allocated within a frame.
#[derive(Clone)]
pub(crate) struct VarStackFrame {
    start: i32,
    used: i32,
    capacity: i32,
}

impl VarStackFrame {
    /// Allocates space for a new variable in the stack.
    ///
    /// # Panics
    ///
    /// Panics if trying to allocate more variables than the frame capacity.
    pub fn new_var(&mut self, ty: Type) -> Var {
        let index = self.used + self.start;
        self.used += 1;
        if self.used > self.capacity {
            panic!("VarStack exceeding its capacity: {}", self.capacity);
        }
        Var { ty, index }
    }
}

/// Represents a variable in the stack.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Var {
    /// The type of the variable
    ty: Type,
    /// The index corresponding to this variable. This index is used for
    /// locating the variable's value in WASM memory. The variable resides at
    /// [`wasm::VARS_STACK_START`] + index * sizeof(i64).
    index: i32,
}

/// A set of YARA rules in compiled form.
///
/// This is the result from [`Compiler::build`].
#[derive(Serialize, Deserialize)]
pub struct Rules {
    /// Pool with identifiers used in the rules. Each identifier has its
    /// own [`IdentId`], which can be used for retrieving the identifier
    /// from the pool as a `&str`.
    ident_pool: StringPool<IdentId>,

    /// Pool with literal strings used in the rules. Each literal has its
    /// own [`LiteralId`], which can be used for retrieving the literal
    /// string as `&BStr`.
    lit_pool: BStringPool<LiteralId>,

    /// Raw data for the WASM module containing the code for rule conditions.
    wasm_mod: Vec<u8>,

    /// WASM module already compiled into native code for the current platform.
    #[serde(skip)]
    compiled_wasm_mod: Option<wasmtime::Module>,

    /// Vector with the names of all the imported modules. The vector contains
    /// the [`IdentId`] corresponding to the module's identifier.
    imported_modules: Vec<IdentId>,

    /// Vector containing all the compiled rules. A [`RuleId`] is an index
    /// in this vector.
    rules: Vec<RuleInfo>,

    /// Total number of patterns in all rules. This is equal to the last
    /// [`PatternId`] +  1.
    num_patterns: usize,

    /// Vector with all the sub-patterns used in the rules. A [`SubPatternId`]
    /// is an index in this vector.
    sub_patterns: Vec<(PatternId, SubPattern)>,

    /// A vector that contains all the atoms generated for the patterns. Each
    /// atom has an associated [`SubPatternId`] that indicates the sub-pattern
    /// it belongs to.
    atoms: Vec<AtomInfo>,

    /// A [`Struct`] in serialized form that contains all the global variables.
    /// Each field in the structure corresponds to a global variable defined
    /// at compile time using [`Compiler::define_global].
    serialized_globals: Vec<u8>,

    /// Aho-Corasick automaton containing the atoms extracted from the patterns.
    /// This allows to search for all the atoms in the scanned data at the same
    /// time in an efficient manner. The automaton is not serialized during when
    /// [`Rules::serialize`] is called, it needs to be wrapped in [`Option`] so
    /// that we can use `#[serde(skip)]` on it because [`AhoCorasick`] doesn't
    /// implement the [`Default`] trait.
    #[serde(skip)]
    ac: Option<AhoCorasick>,
}

impl Rules {
    /// Deserializes the rules from a sequence of bytes produced by
    /// [`Rules::serialize`].
    pub fn deserialize<B>(bytes: B) -> Result<Self, SerializationError>
    where
        B: AsRef<[u8]>,
    {
        let bytes = bytes.as_ref();
        let magic = b"YARA-X";

        if bytes.len() < magic.len() || &bytes[0..magic.len()] != magic {
            return Err(SerializationError::InvalidFormat);
        }

        // Skip the magic and deserialize the remaining data.
        let mut rules = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .deserialize::<Self>(&bytes[magic.len()..])?;

        // The Aho-Corasick automaton is not serialized, it must be rebuilt.
        rules.ac = Some(
            AhoCorasick::new(rules.atoms.iter().map(|x| &x.atom))
                .expect("failed to build Aho-Corasick automaton"),
        );

        // The WASM module must be compiled for the current platform.
        rules.compiled_wasm_mod = Some(
            wasmtime::Module::from_binary(
                &crate::wasm::ENGINE,
                rules.wasm_mod.as_slice(),
            )
            .expect("WASM module is not valid"),
        );

        Ok(rules)
    }

    /// Serializes the rules as a sequence of bytes.
    ///
    /// The [`Rules`] can be restored back by passing the bytes to
    /// [`Rules::deserialize`].
    pub fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = BufWriter::new(Vec::new());
        self.serialize_into(&mut bytes)?;
        Ok(bytes.into_inner().unwrap())
    }

    /// Serializes the rules and writes the bytes into a `writer`.
    pub fn serialize_into<W>(
        &self,
        mut writer: W,
    ) -> Result<(), SerializationError>
    where
        W: Write,
    {
        // Write file header.
        writer.write_all(b"YARA-X")?;

        // Serialize rules.
        Ok(bincode::DefaultOptions::new()
            .with_varint_encoding()
            .serialize_into(writer, self)?)
    }

    /// Returns a [`RuleInfo`] given its [`RuleId`].
    ///
    /// # Panics
    ///
    /// If no rule with such [`RuleId`] exists.
    pub(crate) fn get(&self, rule_id: RuleId) -> &RuleInfo {
        self.rules.get(rule_id.0 as usize).unwrap()
    }

    /// Returns an slice with the individual rules that were compiled.
    #[inline]
    pub(crate) fn rules(&self) -> &[RuleInfo] {
        self.rules.as_slice()
    }

    /// Returns a sub-pattern by [`SubPatternId`].
    #[inline]
    pub(crate) fn get_sub_pattern(
        &self,
        sub_pattern_id: SubPatternId,
    ) -> &(PatternId, SubPattern) {
        &self.sub_patterns[sub_pattern_id.0 as usize]
    }

    #[inline]
    pub(crate) fn atoms(&self) -> &[AtomInfo] {
        self.atoms.as_slice()
    }

    #[inline]
    pub(crate) fn num_patterns(&self) -> usize {
        self.num_patterns
    }

    /// Returns the Aho-Corasick automaton that allows to search for pattern
    /// atoms.
    #[inline]
    pub(crate) fn aho_corasick(&self) -> &AhoCorasick {
        self.ac.as_ref().expect("Aho-Corasick automaton not compiled")
    }

    /// An iterator that yields the name of the modules imported by the
    /// rules.
    pub fn imports(&self) -> Imports {
        Imports {
            iter: self.imported_modules.iter(),
            ident_pool: &self.ident_pool,
        }
    }

    #[inline]
    pub(crate) fn lit_pool(&self) -> &BStringPool<LiteralId> {
        &self.lit_pool
    }

    #[inline]
    pub(crate) fn ident_pool(&self) -> &StringPool<IdentId> {
        &self.ident_pool
    }

    #[inline]
    pub(crate) fn globals(&self) -> Struct {
        bincode::DefaultOptions::new()
            .deserialize::<Struct>(self.serialized_globals.as_slice())
            .expect("error deserializing global variables")
    }

    #[inline]
    pub(crate) fn compiled_wasm_mod(&self) -> &wasmtime::Module {
        self.compiled_wasm_mod.as_ref().expect("WASM module not compiled")
    }
}

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

/// Information about each of the individual rules included in [`Rules`].
#[derive(Serialize, Deserialize)]
pub(crate) struct RuleInfo {
    /// The ID of the namespace the rule belongs to.
    pub(crate) namespace_id: NamespaceId,
    /// The ID of the rule namespace in the identifiers pool.
    pub(crate) namespace_ident_id: IdentId,
    /// The ID of the rule identifier in the identifiers pool.
    pub(crate) ident_id: IdentId,
    /// Span of the rule identifier. This field is ignored while serializing
    /// and deserializing compiles rules, as it is used only during the
    /// compilation phase, but not during the scan phase.
    #[serde(skip)]
    pub(crate) ident_span: Span,
    /// Vector with all the patterns defined by this rule.
    pub(crate) patterns: Vec<(IdentId, PatternId)>,
    /// True if the rule is global.
    pub(crate) is_global: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AtomInfo {
    pub sub_pattern_id: SubPatternId,
    pub atom: Atom,
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
    Fixed { pattern: LiteralId, full_word: FullWord },
    FixedCaseInsensitive { pattern: LiteralId, full_word: FullWord },
    Xor { pattern: LiteralId, full_word: FullWord },
    Base64 { pattern: LiteralId, padding: u8 },
    Base64Wide { pattern: LiteralId, padding: u8 },
    CustomBase64 { pattern: LiteralId, alphabet: LiteralId, padding: u8 },
    CustomBase64Wide { pattern: LiteralId, alphabet: LiteralId, padding: u8 },
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) enum FullWord {
    Disabled,
    Ascii,
    Wide,
}
