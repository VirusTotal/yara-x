use std::mem::size_of;
use std::rc::Rc;

use itertools::Itertools;
use rustc_hash::FxHashSet;

use yara_x_parser::ast::{Ident, WithSpan};
use yara_x_parser::Span;

use crate::compiler::errors::{CompileError, UnknownPattern};
use crate::compiler::ir::{PatternIdx, IR};
use crate::compiler::report::ReportBuilder;
use crate::compiler::{ir, Warnings};
use crate::errors::{UnknownField, UnknownIdentifier};
use crate::modules::BUILTIN_MODULES;
use crate::symbols::{StackedSymbolTable, Symbol, SymbolLookup};
use crate::types::Type;
use crate::wasm;

/// Structure that contains information and data structures required during the
/// compilation of a rule.
pub(crate) struct CompileContext<'a, 'src> {
    /// Builder for creating error and warning reports.
    pub report_builder: &'a ReportBuilder,

    /// IR tree for the rule's condition.
    pub ir: &'a mut IR,

    /// Symbol table that contains the currently defined identifiers, modules,
    /// functions, etc.
    pub symbol_table: &'a mut StackedSymbolTable,

    /// Symbol table for the currently active type.
    ///
    /// When this contains some value, symbols are looked up in this table, and
    /// the main symbol table (i.e: `symbol_table`) is ignored. However, once
    /// the lookup operation is done, this symbol table is set back to `None`.
    pub one_shot_symbol_table: Option<Rc<dyn SymbolLookup + 'a>>,

    /// Reference to a vector that contains the IR for the patterns declared
    /// in the current rule.
    pub current_rule_patterns: &'a mut Vec<ir::PatternInRule<'src>>,

    /// Warnings generated during the compilation.
    pub warnings: &'a mut Warnings,

    /// Enabled features. See [`crate::Compiler::enable_feature`] for details.
    pub features: &'a FxHashSet<String>,

    /// Stack of variables. These are local variables used during the
    /// evaluation of rule conditions, for example for storing loop variables.
    pub vars: VarStack,

    /// Allow invalid escape sequences in regular expressions.
    pub relaxed_re_syntax: bool,

    /// If true, a slow loop produces an error instead of a warning. A slow
    /// rule is one where the upper bound of the loop is potentially large.
    /// Like for example: `for all x in (0..filesize) : (...)`
    pub error_on_slow_loop: bool,

    /// Indicates how deep we are inside `for .. of` statements.
    pub for_of_depth: usize,

    /// Tracks the product of iteration counts of nested loops.
    /// Used to detect loops that may iterate an excessive number of times.
    pub loop_iteration_multiplier: i64,
}

impl<'src> CompileContext<'_, 'src> {
    /// Given a pattern identifier (e.g. `$a`, `#a`, `@a`) search for it in
    /// the current rule and return a tuple containing the [`PatternIdx`]
    /// associated to the pattern and a mutable reference the
    /// [`ir::PatternInRule`] node in the IR.
    ///
    /// Notice that this function accepts identifiers with any of the valid
    /// prefixes `$`, `#`, `@` and `!`.
    pub fn get_pattern_mut(
        &mut self,
        ident: &Ident,
    ) -> Result<(PatternIdx, &mut ir::PatternInRule<'src>), CompileError> {
        // Make sure that identifier starts with `$`, `#`, `@` or `!`.
        debug_assert!("$#@!".contains(
            ident
                .name
                .chars()
                .next()
                .expect("identifier must be at least 1 character long")
        ));

        self.current_rule_patterns
            .iter_mut()
            .find_position(|p| p.identifier().name[1..] == ident.name[1..])
            .map(|(pos, pattern)| (PatternIdx::from(pos), pattern))
            .ok_or_else(|| {
                UnknownPattern::build(
                    self.report_builder,
                    ident.name.to_string(),
                    self.report_builder.span_to_code_loc(ident.span()),
                )
            })
    }

    /// Search for an identifier in the symbol table.
    ///
    /// It first looks into the one-shot symbol table if possible, and then
    /// into the default symbol table. When this function returns the one-shot
    /// symbol table is `None`.
    pub fn lookup(&mut self, ident: &Ident) -> Result<Symbol, CompileError> {
        let symbol_table = self.one_shot_symbol_table.take();

        let symbol = if let Some(symbol_table) = &symbol_table {
            symbol_table.lookup(ident.name)
        } else {
            self.symbol_table.lookup(ident.name)
        };

        if symbol.is_none() {
            // If the current symbol table is `None` it means that the
            // identifier is not a field or method of some structure.
            return if symbol_table.is_none() {
                // Build the error for the unknown identifier.
                let mut err = UnknownIdentifier::build(
                    self.report_builder,
                    ident.name.to_string(),
                    self.report_builder.span_to_code_loc(ident.span()),
                    // Add a note about the missing import statement if
                    // the unknown identifier is a module name.
                    if BUILTIN_MODULES.contains_key(ident.name) {
                        Some(format!(
                            "there is a module named `{}`, but the `import \"{}\"` statement is missing",
                            ident.name,
                            ident.name
                        ))
                    } else {
                        None
                    },
                );
                // If the identifier is a known module, add a fix that inserts
                // the import statement at the beginning of the file.
                if BUILTIN_MODULES.contains_key(ident.name) {
                    err.report_mut().patch(
                        self.report_builder.span_to_code_loc(Span(0..0)),
                        format!("import \"{}\"\n", ident.name),
                    );
                }
                Err(err)
            } else {
                Err(UnknownField::build(
                    self.report_builder,
                    ident.name.to_string(),
                    self.report_builder.span_to_code_loc(ident.span()),
                ))
            };
        }

        Ok(symbol.unwrap())
    }
}

/// Represents a stack of variables.
///
/// The variables stack is composed of frames that are stacked one at the
/// top of another. Each frame can contain one or more variables.
///
/// This stack is stored in WASM main memory, in a memory region that goes
/// from [`wasm::VARS_STACK_START`] to [`wasm::VARS_STACK_END`].
pub(crate) struct VarStack {
    frame_id: usize,
    used: i32,
}

impl VarStack {
    /// Stack frame size for `of` statements.
    pub const OF_FRAME_SIZE: i32 = 5;
    /// Stack frame size for `for .. of` statements.
    pub const FOR_OF_FRAME_SIZE: i32 = 5;
    /// Stack frame size for `for .. in` statements.
    pub const FOR_IN_FRAME_SIZE: i32 = 7;

    /// Creates a stack of variables.
    pub fn new() -> Self {
        Self { used: 0, frame_id: 0 }
    }

    /// Returns the number of variables that are actually used.
    #[cfg(test)]
    pub fn used(&self) -> i32 {
        self.used
    }

    /// Creates a new stack frame with the given capacity on top of the
    /// existing ones. The returned stack frame can hold the specified
    /// number of variables, but not more.
    ///
    /// Use [`VarStackFrame::new_var`] of allocating individual variables
    /// within a frame.
    ///
    /// Each stack frame has its own frame ID, which its unique among all
    /// the frames returned by this function.
    pub fn new_frame(&mut self, capacity: i32) -> VarStackFrame {
        let start = self.used;

        self.used += capacity;
        self.frame_id += 1;

        if self.used > wasm::MAX_VARS {
            panic!("variables stack overflow");
        }

        VarStackFrame { frame_id: self.frame_id, start, capacity, used: 0 }
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
#[derive(Clone, Debug)]
pub(crate) struct VarStackFrame {
    /// Frame ID. This is unique among all past, present, and future
    /// stack frames.
    frame_id: usize,
    /// Offset where the frame starts.
    start: i32,
    /// Maximum number of variables that this frame can hold.
    capacity: i32,
    /// Current number of variables in the frame.
    used: i32,
}

impl VarStackFrame {
    /// Allocates space for a new variable in the stack.
    ///
    /// # Panics
    ///
    /// Panics if trying to allocate more variables than the frame capacity.
    pub fn new_var(&mut self, ty: Type) -> Var {
        if self.used == self.capacity {
            panic!("VarStack exceeding its capacity: {}", self.capacity);
        }
        let index = self.used + self.start;
        self.used += 1;
        Var { frame_id: self.frame_id, ty, index }
    }
}

/// Represents a variable in the stack.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
pub(crate) struct Var {
    /// The frame ID is simply a value that uniquely identify the stack
    /// frame in which this variable resides. The frame ID allows distinguishing
    /// two variables in the IR that have the same type and index, but that
    /// are not actually the same variable.
    frame_id: usize,
    /// The type of the variable.
    ty: Type,
    /// The index corresponding to this variable. This index is used for
    /// locating the variable's value in WASM memory. The variable resides at
    /// [`wasm::VARS_STACK_START`] + index * sizeof(i64).
    index: i32,
}

impl Var {
    pub fn new(frame_id: usize, ty: Type, index: i32) -> Self {
        Self { frame_id, ty, index }
    }

    /// Returns the number of bytes that the variable occupies in memory.
    pub const fn mem_size() -> i32 {
        size_of::<i64>() as i32
    }

    /// Increase the index of this variable by `shift_amount` if the variable
    /// index is equal or larger than `from_index`.
    pub fn shift(&mut self, from_index: i32, shift_amount: i32) {
        if self.index >= from_index {
            self.index += shift_amount;
        }
        if self.index >= wasm::MAX_VARS {
            panic!("variables stack overflow during shift");
        }
    }

    #[cfg(test)]
    pub fn frame_id(&self) -> usize {
        self.frame_id
    }

    #[inline]
    pub fn ty(&self) -> Type {
        self.ty
    }

    #[inline]
    pub fn index(&self) -> i32 {
        self.index
    }
}
