use itertools::Itertools;
use std::mem::size_of;
use std::rc::Rc;

use yara_x_parser::report::ReportBuilder;

use crate::compiler::ir::PatternIdx;
use crate::compiler::{ir, IdentId, RuleId, RuleInfo, Warnings};
use crate::string_pool::StringPool;
use crate::symbols::{StackedSymbolTable, SymbolLookup};
use crate::types::Type;
use crate::wasm;

/// Structure that contains information and data structures required during the
/// current compilation process.
pub(in crate::compiler) struct CompileContext<'a, 'src, 'sym> {
    /// Builder for creating error and warning reports.
    pub report_builder: &'a ReportBuilder,

    /// Symbol table that contains the currently defined identifiers, modules,
    /// functions, etc.
    pub symbol_table: &'a mut StackedSymbolTable<'sym>,

    /// Symbol table for the currently active type. When this contains some
    /// value, symbols are looked up in this table, and the main symbol table
    /// (i.e: `symbol_table`) is ignored.
    pub current_symbol_table: Option<Rc<dyn SymbolLookup + 'a>>,

    /// Information about the rules compiled so far.
    pub rules: &'a Vec<RuleInfo>,

    /// Reference to a vector that contains the IR for the patterns declared
    /// in the current rule.
    pub current_rule_patterns: &'a mut Vec<ir::PatternInRule<'src>>,

    /// Warnings generated during the compilation.
    pub warnings: &'a mut Warnings,

    /// Pool with identifiers used in the rules.
    pub ident_pool: &'a mut StringPool<IdentId>,

    /// Stack of variables. These are local variables used during the
    /// evaluation of rule conditions, for example for storing loop variables.
    pub vars: VarStack,

    /// Allow invalid escape sequences in regular expressions.
    pub relaxed_re_syntax: bool,
}

impl<'a, 'src, 'sym> CompileContext<'a, 'src, 'sym> {
    /// Returns a [`RuleInfo`] given its [`RuleId`].
    ///
    /// # Panics
    ///
    /// If no rule with such [`RuleId`] exists.
    #[inline]
    pub fn get_rule(&self, rule_id: RuleId) -> &RuleInfo {
        self.rules.get(rule_id.0 as usize).unwrap()
    }

    /// Returns the [`RuleInfo`] structure corresponding to the rule currently
    /// being compiled.
    #[inline]
    pub fn get_current_rule(&self) -> &RuleInfo {
        self.rules.last().unwrap()
    }

    /// Given a pattern identifier (e.g. `$a`, `#a`, `@a`) search for it in
    /// the current rule and return its position.
    ///
    /// Notice that this function accepts identifiers with any of the valid
    /// prefixes `$`, `#`, `@` and `!`.
    ///
    /// # Panics
    ///
    /// Panics if the current rule does not have the requested pattern.
    pub fn get_pattern_index(&self, ident: &str) -> PatternIdx {
        // Make sure that identifier starts with `$`, `#`, `@` or `!`.
        debug_assert!("$#@!".contains(
            ident
                .chars()
                .next()
                .expect("identifier must be at least 1 character long")
        ));

        let (position, _) = self
            .current_rule_patterns
            .iter()
            .find_position(|pattern| pattern.identifier()[1..] == ident[1..])
            .expect("pattern not found");

        position.into()
    }

    /// Given a pattern identifier (e.g. `$a`, `#a`, `@a`) search for it in
    /// the current rule and return a mutable reference the [ir::PatternInRule]
    /// node in the IR.
    ///
    /// Notice that this function accepts identifiers with any of the valid
    /// prefixes `$`, `#`, `@` and `!`.
    ///
    /// # Panics
    ///
    /// Panics if the current rule does not have the requested pattern.
    pub fn get_pattern_mut(
        &mut self,
        ident: &str,
    ) -> &mut ir::PatternInRule<'src> {
        // Make sure that identifier starts with `$`, `#`, `@` or `!`.
        debug_assert!("$#@!".contains(
            ident
                .chars()
                .next()
                .expect("identifier must be at least 1 character long")
        ));

        for pattern in self.current_rule_patterns.iter_mut() {
            if pattern.identifier()[1..] == ident[1..] {
                return pattern;
            }
        }

        panic!("pattern `{}` not found", ident);
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
    pub used: i32,
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

        if self.used * Var::mem_size()
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
#[derive(Clone, Debug)]
pub(crate) struct VarStackFrame {
    pub start: i32,
    pub used: i32,
    pub capacity: i32,
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
    pub ty: Type,
    /// The index corresponding to this variable. This index is used for
    /// locating the variable's value in WASM memory. The variable resides at
    /// [`wasm::VARS_STACK_START`] + index * sizeof(i64).
    pub index: i32,
}

impl Var {
    /// Returns the number of bytes that the variable occupies in memory.
    pub(crate) const fn mem_size() -> i32 {
        size_of::<i64>() as i32
    }
}
