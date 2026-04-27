use std::cell::RefCell;
use std::collections::VecDeque;
#[cfg(feature = "rules-profiling")]
use std::iter;
use std::mem::{MaybeUninit, transmute};
#[cfg(feature = "rules-profiling")]
use std::ops::AddAssign;
use std::ops::{Deref, Range};
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::{cmp, mem, thread};

use base64::Engine;
use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use bstr::{BString, ByteSlice};
use indexmap::IndexMap;
use protobuf::{MessageDyn, MessageFull};
use regex_automata::meta::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

use crate::compiler::{
    NamespaceId, PatternId, RegexpId, RuleId, Rules, SubPattern,
    SubPatternAtom, SubPatternFlags, SubPatternId,
};
use crate::errors::VariableError;
use crate::re::Action;
use crate::re::fast::FastVM;
use crate::re::hir::ChainedPatternGap;
use crate::re::thompson::PikeVM;
#[cfg(feature = "rules-profiling")]
use crate::scanner::ProfilingData;
use crate::scanner::matches::{Match, PatternMatches, UnconfirmedMatch};
use crate::scanner::{DataSnippets, ScanError, ScannedData};
use crate::scanner::{HEARTBEAT_COUNTER, INIT_HEARTBEAT};
use crate::types::{Array, Map, Struct, TypeValue};
use crate::wasm::MATCHING_RULES_BITMAP_BASE;
use crate::wasm::runtime::{
    AsContext, AsContextMut, Global, GlobalType, Instance, MemoryType,
    Mutability, Store, TypedFunc, Val, ValType,
};
use crate::{Variable, wasm};

/// Represents the states in which a scanner can be.
pub(crate) enum ScanState<'a> {
    Idle,
    Timeout,
    ScanningData(ScannedData<'a>),
    ScanningBlock((usize, &'a [u8])),
    Finished(DataSnippets<'a>),
}

impl<'a> ScanState<'a> {
    /// Returns changes the current state to [`ScanState::Idle`] and returns
    /// the previous state.
    pub fn take(&mut self) -> ScanState<'a> {
        mem::replace(self, Self::Idle)
    }
}

pub(crate) struct MatchTracker<'r> {
    pub pattern_matches: PatternMatches,
    pub unconfirmed_matches: FxHashMap<SubPatternId, Vec<UnconfirmedMatch>>,
    pub limit_reached: FxHashSet<PatternId>,
    pub compiled_rules: &'r Rules,
}

/// Structure that holds information about WASM memories and variables used
/// during the scan.
pub(crate) struct WasmState {
    pub module: MaybeUninit<Instance>,
    pub main_func: Option<TypedFunc<(), i32>>,
    pub main_memory: Option<wasm::runtime::Memory>,
    pub filesize: Option<Global>,
    pub pattern_search_done: Option<Global>,
    pub store: NonNull<Store<ScanContext<'static, 'static>>>,
}

impl WasmState {
    #[inline]
    pub(crate) fn store_mut<'a>(
        &mut self,
    ) -> &'a mut Store<ScanContext<'static, 'static>> {
        unsafe { self.store.as_mut() }
    }
}

/// Structure that holds information about the current scan.
pub(crate) struct ScanContext<'r, 'd> {
    /// WASM state.
    pub wasm: WasmState,
    /// Map where keys are object handles and values are objects used during
    /// the evaluation of rule conditions. Handles are opaque integer values
    /// that can be passed to and received from WASM code. Each handle identify
    /// an object (string, struct, array or map).
    pub runtime_objects: IndexMap<RuntimeObjectHandle, RuntimeObject>,
    /// The time that can be spent in a scan operation, including the
    /// execution of the rule conditions.
    pub scan_timeout: Option<Duration>,
    /// The number of bytes at the left and right of the matching data
    /// that is stored to provide additional context about where the match
    /// was found.
    pub match_context_size: usize,
    /// The current state of the scanner.
    pub scan_state: ScanState<'d>,
    /// Vector containing the IDs of the rules that matched, including both
    /// global and non-global ones. The rules are added first to the
    /// `matching_rules_per_ns` map, and then moved to this vector
    /// once the scan finishes.
    pub matching_rules: Vec<RuleId>,
    /// Map containing the IDs of rules that matched. Using an `IndexMap`
    /// because we want to keep the insertion order, so that rules in
    /// namespaces that were declared first, appear first in scan results.
    pub matching_rules_per_ns: IndexMap<NamespaceId, Vec<RuleId>>,
    /// Number of private rules that have matched. This will be equal to or
    /// less than the length of `matching_rules`.
    pub num_matching_private_rules: usize,
    /// Number of private rules that did not match.
    pub num_non_matching_private_rules: usize,
    /// Compiled rules for this scan.
    pub compiled_rules: &'r Rules,
    /// Structure that contains top-level symbols, like module names
    /// and external variables. Symbols are normally looked up in this
    /// structure, except if `current_struct` is set to some other
    /// structure that overrides `root_struct`.
    pub root_struct: Struct,
    /// Currently active structure that overrides the `root_struct` if
    /// set.
    pub current_struct: Option<Rc<Struct>>,
    /// Hash map that contains the protobuf messages returned by YARA modules.
    /// Keys are the fully qualified protobuf message name, and values are
    /// the message returned by the main function of the corresponding module.
    pub module_outputs: FxHashMap<String, Box<dyn MessageDyn>>,
    /// Hash map that contains the protobuf messages that has been explicitly
    /// provided by the user to be used as module outputs during the next scan
    /// operation. Keys are the fully qualified protobuf message names, and
    /// values are the protobuf messages set with [`Scanner::set_module_output`].
    pub user_provided_module_outputs: FxHashMap<String, Box<dyn MessageDyn>>,
    /// Match tracker structure that holds unconfirmed and confirmed matches.
    pub tracker: MatchTracker<'r>,
    /// When [`HEARTBEAT_COUNTER`] is larger than this value, the scan is
    /// aborted due to a timeout.
    pub deadline: u64,
    /// Hash map that serves as a cache for regexps used in expressions like
    /// `some_var matches /foobar/`. Compiling a regexp is a expensive
    /// operation. Instead of compiling the regexp each time the expression
    /// is evaluated, it is compiled the first time and stored in this hash
    /// map.
    pub regexp_cache: RefCell<FxHashMap<RegexpId, Regex>>,
    /// Engines for custom base64 alphabets used by base64 string modifiers.
    ///
    /// These engines are derived from rule literals and reused across scans.
    pub custom_base64_engine_cache: Vec<(u32, base64::engine::GeneralPurpose)>,
    /// Callback invoked every time a YARA rule calls `console.log`.
    pub console_log: Option<Box<dyn FnMut(String) + 'r>>,
    /// Virtual Machines used for executing regexps.
    pub vm: VM<'r>,
    /// Hash map that tracks the time spend on each pattern. Keys are pattern
    /// PatternIds and values are the cumulative time spent on verifying each
    /// pattern.
    #[cfg(feature = "rules-profiling")]
    pub time_spent_in_pattern: FxHashMap<PatternId, u64>,
    /// Time spent evaluating each rule. This vector has one entry per rule,
    /// which is the number of nanoseconds spent evaluating the rule.
    #[cfg(feature = "rules-profiling")]
    pub time_spent_in_rule: Vec<u64>,
    /// The time at which the evaluation of the current rule started.
    #[cfg(feature = "rules-profiling")]
    pub rule_execution_start_time: u64,
    /// The ID of the last rule whose condition was executed.
    #[cfg(feature = "rules-profiling")]
    pub last_executed_rule: Option<RuleId>,
    /// Clock used for measuring the time spend on each pattern.
    #[cfg(any(feature = "rules-profiling", feature = "logging"))]
    pub clock: quanta::Clock,
}

#[cfg(feature = "rules-profiling")]
impl ScanContext<'_, '_> {
    /// Returns the slowest N rules.
    ///
    /// Profiling has an accumulative effect. When the scanner is used for
    /// scanning multiple files the times add up.
    pub fn slowest_rules(&self, n: usize) -> Vec<ProfilingData<'_>> {
        debug_assert_eq!(
            self.compiled_rules.num_rules(),
            self.time_spent_in_rule.len()
        );

        let mut result = Vec::with_capacity(self.compiled_rules.num_rules());

        for (rule, condition_exec_time) in iter::zip(
            self.compiled_rules.rules().iter(),
            self.time_spent_in_rule.iter(),
        ) {
            let mut pattern_matching_time = 0;
            for p in rule.patterns.iter() {
                if let Some(d) = self.time_spent_in_pattern.get(&p.pattern_id)
                {
                    pattern_matching_time += *d;
                }
            }

            // Don't track rules that took less 100ms.
            if condition_exec_time + pattern_matching_time > 100_000_000 {
                let namespace = self
                    .compiled_rules
                    .ident_pool()
                    .get(rule.namespace_ident_id)
                    .unwrap();

                let rule = self
                    .compiled_rules
                    .ident_pool()
                    .get(rule.ident_id)
                    .unwrap();

                result.push(ProfilingData {
                    namespace,
                    rule,
                    condition_exec_time: Duration::from_nanos(
                        *condition_exec_time,
                    ),
                    pattern_matching_time: Duration::from_nanos(
                        pattern_matching_time,
                    ),
                });
            }
        }

        // Sort the results by the time spent on each rule, in descending
        // order.
        result.sort_by(|a, b| {
            let a_time = a.pattern_matching_time + a.condition_exec_time;
            let b_time = b.pattern_matching_time + b.condition_exec_time;

            b_time.cmp(&a_time)
        });
        result.truncate(n);
        result
    }

    /// Clears profiling information.
    pub fn clear_profiling_data(&mut self) {
        self.time_spent_in_rule.fill(0);
        self.time_spent_in_pattern.clear();
    }
}

impl ScanContext<'_, '_> {
    const DEFAULT_SCAN_TIMEOUT: u64 = 315_360_000;

    /// Returns a slice with the data being scanned.
    ///
    /// Returns `None` if the current scan state is not [`ScanState::ScanningData`].
    /// Particularly, if the state is [`ScanState::ScanningBlock`] the result is
    /// `None`.
    pub(crate) fn scanned_data(&self) -> Option<&[u8]> {
        match &self.scan_state {
            ScanState::ScanningData(data) => Some(data.as_ref()),
            _ => None,
        }
    }

    #[inline]
    pub(crate) fn wasm_store_mut<'a>(
        &mut self,
    ) -> &'a mut Store<ScanContext<'static, 'static>> {
        self.wasm.store_mut()
    }

    /// Returns true of the regexp identified by the given [`RegexpId`]
    /// matches `haystack`.
    pub(crate) fn regexp_matches(
        &self,
        regexp_id: RegexpId,
        haystack: &[u8],
    ) -> bool {
        self.regexp_cache
            .borrow_mut()
            .entry(regexp_id)
            .or_insert_with(|| self.compiled_rules.get_regexp(regexp_id))
            .is_match(haystack)
    }

    /// Returns the protobuf struct produced by a module.
    ///
    /// The main function of a module returns a protobuf message with data
    /// produced by the module for the current scan. Accessing this data
    /// from some other function exported by the module is useful in certain
    /// cases, and that's the purpose of this function.
    ///
    /// This function is generic over `T`, where `T` is some protobuf message
    /// type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::modules::protos::my_module::MyModuleProto;
    /// let module_data: MyModuleProto = ctx.module_data::<MyModuleProto>()
    /// ```
    pub(crate) fn module_output<T: MessageFull>(&self) -> Option<&T> {
        let m = self.module_outputs.get(T::descriptor().full_name())?.as_ref();
        <dyn MessageDyn>::downcast_ref(m)
    }

    pub(crate) fn console_log(&mut self, message: String) {
        if let Some(console_log) = &mut self.console_log {
            console_log(message)
        }
    }

    /// Sets the value of a global variable.
    pub fn set_global<T: TryInto<Variable>>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<&mut Self, VariableError>
    where
        VariableError: From<<T as TryInto<Variable>>::Error>,
    {
        if let Some(field) = self.root_struct.field_by_name_mut(ident) {
            let variable: Variable = value.try_into()?;
            let type_value: TypeValue = variable.into();
            // The new type must match the old one.
            if type_value.eq_type(&field.type_value) {
                field.type_value = type_value;
            } else {
                return Err(VariableError::InvalidType {
                    variable: ident.to_string(),
                    expected_type: field.type_value.ty().to_string(),
                    actual_type: type_value.ty().to_string(),
                });
            }
        } else {
            return Err(VariableError::Undefined(ident.to_string()));
        }

        Ok(self)
    }

    pub(crate) fn store_struct(
        &mut self,
        s: Rc<Struct>,
    ) -> RuntimeObjectHandle {
        let obj_ref = RuntimeObjectHandle(Rc::<Struct>::as_ptr(&s) as i64);
        self.runtime_objects.insert_full(obj_ref, RuntimeObject::Struct(s));
        obj_ref
    }

    pub(crate) fn store_array(&mut self, a: Rc<Array>) -> RuntimeObjectHandle {
        let obj_ref = RuntimeObjectHandle(Rc::<Array>::as_ptr(&a) as i64);
        self.runtime_objects.insert_full(obj_ref, RuntimeObject::Array(a));
        obj_ref
    }

    pub(crate) fn store_map(&mut self, m: Rc<Map>) -> RuntimeObjectHandle {
        let obj_ref = RuntimeObjectHandle(Rc::<Map>::as_ptr(&m) as i64);
        self.runtime_objects.insert_full(obj_ref, RuntimeObject::Map(m));
        obj_ref
    }

    pub(crate) fn store_string(
        &mut self,
        s: Rc<BString>,
    ) -> RuntimeObjectHandle {
        let obj_ref = RuntimeObjectHandle(Rc::<BString>::as_ptr(&s) as i64);
        self.runtime_objects.insert_full(obj_ref, RuntimeObject::String(s));
        obj_ref
    }

    /// Gets the value of the global variable `filesize`.
    pub(crate) fn get_filesize(&mut self) -> i64 {
        self.wasm.filesize.unwrap().get(self.wasm_store_mut()).i64().unwrap()
    }

    /// Set the value of the global variable `filesize`.
    pub(crate) fn set_filesize(&mut self, filesize: i64) {
        self.wasm
            .filesize
            .unwrap()
            .set(self.wasm_store_mut(), Val::I64(filesize))
            .unwrap();
    }

    /// Sets the value of the flag that indicates if the pattern search
    /// phase was already executed.
    pub(crate) fn set_pattern_search_done(&mut self, done: bool) {
        self.wasm
            .pattern_search_done
            .unwrap()
            .set(self.wasm_store_mut(), Val::I32(done as i32))
            .unwrap();
    }

    /// Sets a timeout for scan operations.
    pub(crate) fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.scan_timeout = Some(timeout);
        self
    }

    /// Invokes the main function, which evaluates the rules' conditions. It
    /// calls ScanContext::search_for_patterns (which does the Aho-Corasick
    /// scanning) only if necessary.
    ///
    /// This will return [ScanError::Timeout], if a timeout occurs while
    /// searching for patterns or evaluating the conditions.
    pub(crate) fn eval_conditions(&mut self) -> Result<(), ScanError> {
        // Save the time in which the evaluation started.
        #[cfg(feature = "rules-profiling")]
        {
            self.rule_execution_start_time = self.clock.raw();
        }
        // Invoke the main function, which evaluates the rules' conditions. It
        // calls ScanContext::search_for_patterns (which does the Aho-Corasick
        // scanning) only if necessary.
        //
        // This will return Err(ScanError::Timeout), when the scan timeout is
        // reached while WASM code is being executed.
        let store = self.wasm_store_mut();
        let eval_result =
            self.wasm.main_func.as_ref().unwrap().call(store, ());

        #[cfg(feature = "rules-profiling")]
        if eval_result.is_err() {
            // If a timeout occurs, the methods `ctx.track_rule_no_match` or
            // `ctx.track_rule_match` may not be invoked for the currently
            // executing rule. This means that the time spent within that rule
            // has not been recorded yet, so we need to update it here.
            //
            // The ID of the rule that was running during the timeout can be
            // determined as the one immediately following the last executed
            // rule, based on the assumption that rules are processed in a
            // strictly ascending ID order.
            //
            // Additionally, if the timeout happens after `ctx.last_executed_rule`
            // has been updated with the last rule ID, we might end up calling
            // `update_time_spent_in_rule` with an ID that is off by one.
            // However, this function is designed to handle such cases
            // gracefully.
            self.update_time_spent_in_rule(
                self.last_executed_rule
                    .map_or(RuleId::from(0), |rule_id| rule_id.next()),
            );
        }

        #[cfg(all(feature = "rules-profiling", feature = "logging"))]
        {
            let most_expensive_rules = self.slowest_rules(10);
            if !most_expensive_rules.is_empty() {
                log::info!("Most expensive rules:");
                for profiling_data in most_expensive_rules {
                    log::info!("+ namespace: {}", profiling_data.namespace);
                    log::info!("  rule: {}", profiling_data.rule);
                    log::info!(
                        "  pattern matching time: {:?}",
                        profiling_data.pattern_matching_time
                    );
                    log::info!(
                        "  condition execution time: {:?}",
                        profiling_data.condition_exec_time
                    );
                }
            }
        }

        // `matching_rules` must be empty at this point. Matching rules were
        // being tracked by the `matching_rules_per_ns` map, but we are about
        // to move them to `matching_rules` while leaving the map empty.
        assert!(self.matching_rules.is_empty());

        // Move the matching rules to the `matching_rules` vector, leaving the
        // `matching_rules_per_ns` map empty.
        for rules in self.matching_rules_per_ns.values_mut() {
            for rule_id in rules.drain(0..) {
                self.matching_rules.push(rule_id);
            }
        }

        // The WASM code that evaluates the conditions returns
        // `ScanError::Timeout` if a timeout occurs during its execution.
        // However, a timeout may also happen while `search_for_patterns`
        // is running. In that case, the function returns `Ok(0)` but the
        // scan state is updated to `ScanState::Timeout`.
        match eval_result {
            Ok(0) => match self.scan_state {
                ScanState::Timeout => Err(ScanError::Timeout),
                _ => Ok(()),
            },
            Ok(v) => panic!("WASM main returned: {v}"),
            Err(err) if err.is::<ScanError>() => {
                Err(err.downcast::<ScanError>().unwrap())
            }
            Err(err) => panic!(
                "unexpected error while executing WASM main function: {err}"
            ),
        }
    }

    /// Resets the scan context to its initial state, making it ready for
    /// another scan.
    ///
    /// This clears all the information generated during the previous scan and
    /// resets the deadline for timeouts.
    pub(crate) fn reset(&mut self) {
        let num_rules = self.compiled_rules.num_rules();
        let num_patterns = self.compiled_rules.num_patterns();

        self.scan_state = ScanState::Idle;

        // Free all runtime objects left around by previous scans.
        self.runtime_objects.clear();

        // Clear the array that tracks the patterns that reached the maximum
        // number of patterns.
        self.tracker.limit_reached.clear();

        self.tracker.unconfirmed_matches.clear();
        self.num_matching_private_rules = 0;
        self.num_non_matching_private_rules = 0;

        // Clear the value of `current_struct` as it may contain a reference
        // to some struct.
        self.current_struct = None;

        // Clear module outputs from previous scans.
        self.module_outputs.clear();

        // Move the matching rules to the `matching_rules` vector, leaving the
        // `matching_rules_per_ns` map empty.
        for rules in self.matching_rules_per_ns.values_mut() {
            for rule_id in rules.drain(0..) {
                self.matching_rules.push(rule_id);
            }
        }

        // If some pattern or rule matched, clear the matches. Notice that a
        // rule may match without any pattern being matched, because there
        // are rules without patterns, or that match if the pattern is not
        // found.
        if !self.tracker.pattern_matches.is_empty()
            || !self.matching_rules.is_empty()
        {
            self.tracker.pattern_matches.clear();
            self.matching_rules.clear();

            let store = self.wasm_store_mut();
            let mem = self.wasm.main_memory.unwrap().data_mut(store);

            // Starting at MATCHING_RULES_BITMAP in main memory there's a
            // bitmap were the N-th bit indicates if the rule with ID = N
            // matched or not, If some rule matched in a previous call the
            // bitmap will contain some bits set to 1 and need to be cleared.
            let base = MATCHING_RULES_BITMAP_BASE as usize;
            let bitmap = BitSlice::<_, Lsb0>::from_slice_mut(
                &mut mem[base..base
                    + num_rules.div_ceil(8)
                    + num_patterns.div_ceil(8)],
            );

            // Set to zero all bits in the bitmap.
            bitmap.fill(false);
        }

        // Timeout in seconds. This is either the value provided by the user or
        // 315.360.000 which is the number of seconds in a year. Using u64::MAX
        // doesn't work because this value is added to the current epoch, and
        // will cause an overflow. We need an integer large enough, but that
        // has room before the u64 limit is reached. For this same reason if
        // the user specifies a value larger than 315.360.000 we limit it to
        // 315.360.000 anyway. One year should be enough, I hope you don't plan
        // to run a YARA scan that takes longer.
        let timeout_secs =
            self.scan_timeout.map_or(Self::DEFAULT_SCAN_TIMEOUT, |t| {
                cmp::min(
                    t.as_secs_f32().ceil() as u64,
                    Self::DEFAULT_SCAN_TIMEOUT,
                )
            });

        self.deadline =
            HEARTBEAT_COUNTER.load(Ordering::Relaxed) + timeout_secs;

        let wasm_store = self.wasm_store_mut();

        // Sets the deadline for the WASM store. The WASM main function
        // will abort if the deadline is reached while the function is being
        // executed.
        wasm_store.set_epoch_deadline(timeout_secs);
        wasm_store.epoch_deadline_callback(|_| Err(ScanError::Timeout.into()));

        // If some timeout was specified, start the heartbeat thread, if
        // not previously started. The heartbeat thread increments the WASM
        // engine epoch and HEARTBEAT_COUNTER every second. There's a single
        // instance of this thread, independently of the number of concurrent
        // scans.
        if self.scan_timeout.is_some() {
            INIT_HEARTBEAT.call_once(|| {
                thread::spawn(|| {
                    loop {
                        thread::sleep(Duration::from_secs(1));
                        wasm::get_engine().increment_epoch();
                        HEARTBEAT_COUNTER
                            .fetch_update(
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                                |x| Some(x + 1),
                            )
                            .unwrap();
                    }
                });
            });
        }
    }

    /// Update the time spent in the rule with the given ID, the time is
    /// increased by the time elapsed since `rule_execution_start_time`.
    #[cfg(feature = "rules-profiling")]
    pub(crate) fn update_time_spent_in_rule(&mut self, rule_id: RuleId) {
        // The RuleId is not guaranteed to be a valid one. It may be larger
        // than the last RuleId, so we can't assume that the `get_mut` will
        // be successful.
        if let Some(time_spend_in_rule) =
            self.time_spent_in_rule.get_mut::<usize>(rule_id.into())
        {
            time_spend_in_rule.add_assign(self.clock.delta_as_nanos(
                self.rule_execution_start_time,
                self.clock.raw(),
            ));
        }
    }

    /// Called during the scan process when a rule didn't match.
    pub(crate) fn track_rule_no_match(&mut self, rule_id: RuleId) {
        #[cfg(feature = "rules-profiling")]
        {
            self.last_executed_rule = Some(rule_id);
            self.update_time_spent_in_rule(rule_id);
        }

        let rule = self.compiled_rules.get(rule_id);

        if rule.is_private {
            self.num_non_matching_private_rules += 1;
        }

        // If the rule is global, all the rules in the same namespace that
        // matched previously must be removed from the `matching_rules_per_ns`
        // map. Also, their corresponding bits in the matching rules bitmap must
        // be cleared, and `num_matching_private_rules` must be decremented if
        // the rule was private and `num_non_matching_private_rules` incremented.
        if rule.is_global
            && let Some(rules) =
                self.matching_rules_per_ns.get_mut(&rule.namespace_id)
        {
            let store = self.wasm.store_mut();
            let main_mem = self.wasm.main_memory.unwrap().data_mut(store);

            let base = MATCHING_RULES_BITMAP_BASE as usize;
            let num_rules = self.compiled_rules.num_rules();

            let bits = BitSlice::<u8, Lsb0>::from_slice_mut(
                &mut main_mem[base..base + num_rules.div_ceil(8)],
            );

            for rule_id in rules.drain(0..) {
                if self.compiled_rules.get(rule_id).is_private {
                    self.num_matching_private_rules -= 1;
                    self.num_non_matching_private_rules += 1;
                }
                bits.set(rule_id.into(), false);
            }
        }

        // Save the time in which the evaluation of the next rule started.
        #[cfg(feature = "rules-profiling")]
        {
            self.rule_execution_start_time = self.clock.raw();
        }
    }

    /// Called during the scan process when a rule has matched for tracking
    /// the matching rules.
    pub(crate) fn track_rule_match(&mut self, rule_id: RuleId) {
        #[cfg(feature = "rules-profiling")]
        {
            self.last_executed_rule = Some(rule_id);
            self.update_time_spent_in_rule(rule_id);
        }

        let rule = self.compiled_rules.get(rule_id);

        #[cfg(feature = "logging")]
        log::info!(
            "Rule match: {}:{}  {:?}",
            self.compiled_rules
                .ident_pool()
                .get(rule.namespace_ident_id)
                .unwrap(),
            self.compiled_rules.ident_pool().get(rule.ident_id).unwrap(),
            rule_id,
        );

        self.matching_rules_per_ns
            .entry(rule.namespace_id)
            .or_default()
            .push(rule_id);

        if rule.is_private {
            self.num_matching_private_rules += 1;
        }

        let wasm_store = self.wasm_store_mut();
        let mem = self.wasm.main_memory.unwrap().data_mut(wasm_store);
        let num_rules = self.compiled_rules.num_rules();

        let base = MATCHING_RULES_BITMAP_BASE as usize;
        let bits = BitSlice::<u8, Lsb0>::from_slice_mut(
            &mut mem[base..base + num_rules.div_ceil(8)],
        );

        // The RuleId-th bit in the `rule_matches` bit vector is set to 1.
        bits.set(rule_id.into(), true);

        // Save the time in which the evaluation of the next rule started.
        #[cfg(feature = "rules-profiling")]
        {
            self.rule_execution_start_time = self.clock.raw();
        }
    }

    /// The Aho-Corasick search loop.
    pub(crate) fn ac_search_loop(
        &mut self,
        base: usize,
        data: &[u8],
        block_scanning_mode: bool,
    ) -> Result<(), ScanError> {
        let ac = self.compiled_rules.ac_automaton();
        let atoms = self.compiled_rules.atoms();
        let filesize = self.get_filesize();

        #[cfg(feature = "logging")]
        let mut atom_matches = 0_usize;

        for ac_match in ac.find_overlapping_iter(data) {
            #[cfg(feature = "logging")]
            {
                atom_matches += 1;
            }

            if HEARTBEAT_COUNTER.load(Ordering::Relaxed) >= self.deadline {
                return Err(ScanError::Timeout);
            }

            let atom =
                unsafe { atoms.get_unchecked(ac_match.pattern().as_usize()) };

            // Subtract the backtrack value from the offset where the atom
            // matched. If the result is negative the atom can't be inside
            // the scanned data and therefore is not a possible match.
            let atom_pos = if let Some(atom_pos) =
                ac_match.start().checked_sub(atom.backtrack())
            {
                atom_pos
            } else {
                continue;
            };

            // Each atom belongs to a sub-pattern.
            let sub_pattern_id = atom.sub_pattern_id();

            // Each sub-pattern belongs to a pattern.
            let (pattern_id, sub_pattern) =
                &self.compiled_rules.get_sub_pattern(sub_pattern_id);

            // Check if the potentially matching pattern has reached the
            // maximum number of allowed matches. In that case continue without
            // verifying the match.
            if self.tracker.limit_reached.contains(pattern_id) {
                continue;
            }

            // If there are file size bounds associated to the pattern, but
            // the currently scanned file does not satisfy them, no further
            // confirmation is needed. The rule won't match regardless of
            // whether the pattern matches or not. This is not done in block
            // scanning mode as `filesize` is undefined in that mode.
            if !block_scanning_mode
                && let Some(bounds) =
                    self.compiled_rules.filesize_bounds(*pattern_id)
                && !bounds.contains(filesize)
            {
                continue;
            }

            #[cfg(feature = "rules-profiling")]
            let verification_start = self.clock.raw();

            // If the atom is exact no further verification is needed, except
            // for making sure that the fullword requirements are met. An exact
            // atom is enough to guarantee that the whole sub-pattern matched.
            #[cfg(feature = "exact-atoms")]
            if atom.is_exact() {
                let flags = match sub_pattern {
                    SubPattern::Literal { flags, .. }
                    | SubPattern::LiteralChainHead { flags, .. }
                    | SubPattern::LiteralChainTail { flags, .. }
                    | SubPattern::Regexp { flags, .. }
                    | SubPattern::RegexpChainHead { flags, .. }
                    | SubPattern::RegexpChainTail { flags, .. } => flags,
                    _ => unreachable!(),
                };

                let match_range = atom_pos..atom_pos + atom.len();

                if verify_full_word(data, &match_range, *flags, None) {
                    handle_sub_pattern_match(
                        &mut self.tracker,
                        &mut self.wasm,
                        sub_pattern_id,
                        sub_pattern,
                        *pattern_id,
                        Match::new(match_range).rebase(base),
                    );
                }

                continue;
            }

            match sub_pattern {
                SubPattern::Literal { pattern, flags, .. }
                | SubPattern::LiteralChainHead { pattern, flags, .. }
                | SubPattern::LiteralChainTail { pattern, flags, .. } => {
                    let pattern = self
                        .compiled_rules
                        .lit_pool()
                        .get_bytes(*pattern)
                        .unwrap();

                    if verify_literal_match(pattern, data, atom_pos, *flags) {
                        handle_sub_pattern_match(
                            &mut self.tracker,
                            &mut self.wasm,
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            Match::new(atom_pos..atom_pos + pattern.len())
                                .rebase(base),
                        );
                    }
                }
                SubPattern::Regexp { flags, .. }
                | SubPattern::RegexpChainHead { flags, .. }
                | SubPattern::RegexpChainTail { flags, .. } => {
                    verify_regexp_match(
                        &mut self.vm,
                        data,
                        atom_pos,
                        atom,
                        *flags,
                        |match_range| {
                            handle_sub_pattern_match(
                                &mut self.tracker,
                                &mut self.wasm,
                                sub_pattern_id,
                                sub_pattern,
                                *pattern_id,
                                Match::new(match_range).rebase(base),
                            );
                        },
                    )
                }

                SubPattern::Xor { pattern, flags } => {
                    let pattern = self
                        .compiled_rules
                        .lit_pool()
                        .get_bytes(*pattern)
                        .unwrap();

                    if let Some(key) =
                        verify_xor_match(pattern, data, atom_pos, atom, *flags)
                    {
                        handle_sub_pattern_match(
                            &mut self.tracker,
                            &mut self.wasm,
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            Match::new(atom_pos..atom_pos + pattern.len())
                                .rebase(base)
                                .xor_key(key),
                        );
                    }
                }

                SubPattern::Base64 { pattern, padding }
                | SubPattern::Base64Wide { pattern, padding } => {
                    if let Some(match_range) = verify_base64_match(
                        self.compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap(),
                        data,
                        (*padding).into(),
                        atom_pos,
                        &base64::engine::general_purpose::STANDARD_NO_PAD,
                        matches!(sub_pattern, SubPattern::Base64Wide { .. }),
                    ) {
                        handle_sub_pattern_match(
                            &mut self.tracker,
                            &mut self.wasm,
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            Match::new(match_range).rebase(base),
                        );
                    }
                }

                SubPattern::CustomBase64 { pattern, alphabet, padding }
                | SubPattern::CustomBase64Wide {
                    pattern,
                    alphabet,
                    padding,
                } => {
                    let alphabet_id = (*alphabet).into();
                    let compiled_rules = self.compiled_rules;
                    let base64_engine = custom_base64_engine(
                        &mut self.custom_base64_engine_cache,
                        alphabet_id,
                        || {
                            let alphabet = compiled_rules
                                .lit_pool()
                                .get_str(*alphabet)
                                .unwrap();
                            let alphabet =
                                base64::alphabet::Alphabet::new(alphabet)
                                    .unwrap();
                            base64::engine::GeneralPurpose::new(
                                &alphabet,
                                base64::engine::general_purpose::NO_PAD,
                            )
                        },
                    );

                    if let Some(match_range) = verify_base64_match(
                        self.compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap(),
                        data,
                        (*padding).into(),
                        atom_pos,
                        base64_engine,
                        matches!(
                            sub_pattern,
                            SubPattern::CustomBase64Wide { .. }
                        ),
                    ) {
                        handle_sub_pattern_match(
                            &mut self.tracker,
                            &mut self.wasm,
                            sub_pattern_id,
                            sub_pattern,
                            *pattern_id,
                            Match::new(match_range).rebase(base),
                        );
                    }
                }
            };

            #[cfg(feature = "rules-profiling")]
            {
                let time_spent = self
                    .clock
                    .delta_as_nanos(verification_start, self.clock.raw());

                self.time_spent_in_pattern
                    .entry(*pattern_id)
                    .and_modify(|t| {
                        t.add_assign(time_spent);
                    })
                    .or_insert(time_spent);
            }
        }

        #[cfg(feature = "logging")]
        log::info!("Atom matches: {}", atom_matches);

        Ok(())
    }

    /// Search for patterns in the scanned data.
    ///
    /// The pattern search phase is when YARA scans the data looking for the
    /// patterns declared in rules. All the patterns are searched simultaneously
    /// using the Aho-Corasick algorithm. This phase is triggered lazily during
    /// the evaluation of the rule conditions, when some of the conditions need
    /// to know if a pattern matched or not.
    ///
    /// This function won't be called if the conditions can be fully evaluated
    /// without looking for any of the patterns. If it must be called, it will be
    /// called only once.
    ///
    /// In case of timeout, this function returns [ScanError::Timeout] and sets
    /// the scan state to [ScanState::Timeout].
    pub(crate) fn search_for_patterns(&mut self) -> Result<(), ScanError> {
        // Take ownership of the scan state, while searching for
        // the patterns, `self.scan_state` is left as `Idle`.
        let state = self.scan_state.take();

        let (base, data, block_scanning_mode) = match &state {
            ScanState::ScanningData(data) => (0, data.as_ref(), false),
            ScanState::ScanningBlock((base, data)) => (*base, *data, true),
            _ => panic!(),
        };

        #[cfg(any(feature = "rules-profiling", feature = "logging"))]
        let scan_start = self.clock.raw();

        // Verify the anchored pattern first. These are patterns that can
        // match at a single known offset within the data.
        self.verify_anchored_patterns(base, data);

        let result = match self.ac_search_loop(base, data, block_scanning_mode)
        {
            Ok(_) => {
                self.scan_state = state;
                Ok(())
            }
            Err(ScanError::Timeout) => {
                self.scan_state = ScanState::Timeout;
                Err(ScanError::Timeout)
            }
            _ => unreachable!(),
        };

        // Indicate that the pattern search phase was already done.
        self.set_pattern_search_done(true);

        #[cfg(any(feature = "rules-profiling", feature = "logging"))]
        let scan_end = self.clock.raw();

        // Adjust the rule evaluation start time to exclude the time spent
        // searching for patterns. Since the `search_for_pattern` function
        // is invoked lazily during the evaluation of some rule, the overall
        // evaluation time for that rule may appear longer. To ensure that
        // search time is not attributed to the rule, we need to adjust
        // `rule_evaluation_start_time` accordingly.
        #[cfg(feature = "rules-profiling")]
        {
            self.rule_execution_start_time +=
                scan_end.saturating_sub(scan_start);
        }

        #[cfg(feature = "logging")]
        {
            log::info!(
                "Scan time: {:?}",
                self.clock.delta(scan_start, scan_end)
            );
        }

        result
    }

    fn verify_anchored_patterns(&mut self, base: usize, data: &[u8]) {
        for (sub_pattern_id, (pattern_id, sub_pattern)) in self
            .compiled_rules
            .anchored_sub_patterns()
            .iter()
            .map(|id| (id, self.compiled_rules.get_sub_pattern(*id)))
        {
            match sub_pattern {
                SubPattern::Literal {
                    pattern,
                    flags,
                    anchored_at: Some(offset),
                    ..
                } => {
                    // Make the offset relative to the block's base. If an
                    // overflow occurs is because the block's base is larger
                    // than the offset, in such cases the match can't occur.
                    if let (offset, false) = offset.overflowing_sub(base) {
                        let pattern = self
                            .compiled_rules
                            .lit_pool()
                            .get_bytes(*pattern)
                            .unwrap();

                        if verify_literal_match(pattern, data, offset, *flags)
                        {
                            handle_sub_pattern_match(
                                &mut self.tracker,
                                &mut self.wasm,
                                *sub_pattern_id,
                                sub_pattern,
                                *pattern_id,
                                Match::new(offset..offset + pattern.len())
                                    .rebase(base),
                            );
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

/// Verifies if a literal `pattern` matches at `match_start` in `scanned_data`.
fn verify_literal_match(
    pattern: &[u8],
    scanned_data: &[u8],
    match_start: usize,
    flags: SubPatternFlags,
) -> bool {
    // Offset where the match should end (exclusive).
    let match_end = match_start + pattern.len();

    // The match can not end past the end of the scanned data.
    if match_end > scanned_data.len() {
        return false;
    }

    if flags.intersects(
        SubPatternFlags::FullwordLeft | SubPatternFlags::FullwordRight,
    ) && !verify_full_word(
        scanned_data,
        &(match_start..match_end),
        flags,
        None,
    ) {
        return false;
    }

    if flags.contains(SubPatternFlags::Nocase) {
        pattern.eq_ignore_ascii_case(&scanned_data[match_start..match_end])
    } else {
        &scanned_data[match_start..match_end] == pattern.as_bytes()
    }
}

/// Returns true if the match delimited by `match_range` is a full word match.
/// This means that the bytes before the range's start and after the range's
/// end are both non-alphanumeric.
fn verify_full_word(
    scanned_data: &[u8],
    match_range: &Range<usize>,
    flags: SubPatternFlags,
    xor_key: Option<u8>,
) -> bool {
    let xor_key = xor_key.unwrap_or(0);

    if flags.contains(SubPatternFlags::Wide) {
        if flags.contains(SubPatternFlags::FullwordLeft)
            && match_range.start >= 2
            && (scanned_data[match_range.start - 1] ^ xor_key) == 0
            && (scanned_data[match_range.start - 2] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
        if flags.contains(SubPatternFlags::FullwordRight)
            && match_range.end + 1 < scanned_data.len()
            && (scanned_data[match_range.end + 1] ^ xor_key) == 0
            && (scanned_data[match_range.end] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
    } else {
        if flags.contains(SubPatternFlags::FullwordLeft)
            && match_range.start >= 1
            && (scanned_data[match_range.start - 1] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
        if flags.contains(SubPatternFlags::FullwordRight)
            && match_range.end < scanned_data.len()
            && (scanned_data[match_range.end] ^ xor_key)
                .is_ascii_alphanumeric()
        {
            return false;
        }
    }

    true
}

fn verify_chain_of_matches(
    tracker: &mut MatchTracker,
    wasm_state: &mut WasmState,
    pattern_id: PatternId,
    tail_sub_pattern_id: SubPatternId,
    tail_match: Match,
) {
    let mut queue = VecDeque::new();

    queue.push_back((
        tail_sub_pattern_id,
        UnconfirmedMatch { range: tail_match.range.clone(), chain_length: 1 },
    ));

    let mut tail_chained_to: Option<SubPatternId> = None;

    while let Some((id, current_match)) = queue.pop_front() {
        match &tracker.compiled_rules.get_sub_pattern(id).1 {
            SubPattern::LiteralChainHead { flags, .. }
            | SubPattern::RegexpChainHead { flags, .. } => {
                track_pattern_match(
                    tracker,
                    wasm_state,
                    pattern_id,
                    Match {
                        base: tail_match.base,
                        range: current_match.range.start..tail_match.range.end,
                        xor_key: None,
                    },
                    flags.contains(SubPatternFlags::GreedyRegexp),
                );

                let mut next_pattern_id = tail_chained_to;

                while let Some(id) = next_pattern_id {
                    if let Some(unconfirmed_matches) =
                        tracker.unconfirmed_matches.get_mut(&id)
                    {
                        unconfirmed_matches
                            .iter_mut()
                            .for_each(|m| m.chain_length = 0);
                    }
                    let (_, sub_pattern) =
                        tracker.compiled_rules.get_sub_pattern(id);
                    next_pattern_id = sub_pattern.chained_to();
                }
            }
            SubPattern::LiteralChainTail {
                chained_to, gap, flags, ..
            }
            | SubPattern::RegexpChainTail { chained_to, gap, flags, .. } => {
                let unconfirmed_matches =
                    match tracker.unconfirmed_matches.get_mut(chained_to) {
                        Some(m) => m,
                        None => continue,
                    };

                for m in unconfirmed_matches {
                    let in_range = match gap {
                        ChainedPatternGap::Bounded(gap) => {
                            let min_gap = *gap.start() as usize;
                            let max_gap = *gap.end() as usize;
                            (m.range.end + min_gap..=m.range.end + max_gap)
                                .contains(&current_match.range.start)
                        }
                        ChainedPatternGap::Unbounded(gap) => {
                            let min_gap = gap.start as usize;
                            (m.range.end + min_gap..)
                                .contains(&current_match.range.start)
                        }
                    };
                    if in_range && m.chain_length <= current_match.chain_length
                    {
                        m.chain_length = current_match.chain_length + 1;
                        queue.push_back((*chained_to, m.clone()))
                    }
                }

                if flags.contains(SubPatternFlags::LastInChain)
                    && flags.contains(SubPatternFlags::GreedyRegexp)
                {
                    tail_chained_to = Some(*chained_to);
                }
            }
            _ => unreachable!(),
        };
    }
}

/// When some `atom` belonging to a regexp is found at `match_start`, verify
/// that the regexp actually matches.
///
/// This function can produce multiple matches, `f` is called for every
/// match found.
fn verify_regexp_match(
    vm: &mut VM,
    scanned_data: &[u8],
    match_start: usize,
    atom: &SubPatternAtom,
    flags: SubPatternFlags,
    mut f: impl FnMut(Range<usize>),
) {
    let mut fwd_match_len = None;

    // If the atom has some forward code, that's the code that should execute
    // the VM for matching the portion that pattern that comes after the atom.
    // The type of VM used depends on whether the pattern was compiled for the
    // faster and less general FastVM, or for the slower but more general
    // PikeVM.
    if let Some(fwd_code) = atom.fwd_code() {
        if flags.contains(SubPatternFlags::FastRegexp) {
            vm.fast_vm.try_match(
                fwd_code,
                &scanned_data[match_start..],
                flags.contains(SubPatternFlags::Wide),
                |match_len| {
                    fwd_match_len = Some(match_len);
                    if flags.contains(SubPatternFlags::GreedyRegexp) {
                        Action::Continue
                    } else {
                        Action::Stop
                    }
                },
            );
        } else {
            vm.pike_vm.try_match(
                fwd_code,
                &scanned_data[match_start..],
                &scanned_data[..match_start],
                flags.contains(SubPatternFlags::Wide),
                |match_len| {
                    fwd_match_len = Some(match_len);
                    Action::Stop
                },
            );
        }
    } else {
        fwd_match_len = Some(atom.len());
    }

    let fwd_match_len = match fwd_match_len {
        Some(len) => len,
        None => return,
    };

    if let Some(bck_code) = atom.bck_code() {
        if flags.contains(SubPatternFlags::FastRegexp) {
            vm.fast_vm.try_match(
                bck_code,
                &scanned_data[..match_start],
                flags.contains(SubPatternFlags::Wide),
                |bck_match_len| {
                    let range = match_start - bck_match_len
                        ..match_start + fwd_match_len;
                    if verify_full_word(scanned_data, &range, flags, None) {
                        f(range);
                    }
                    Action::Continue
                },
            );
        } else {
            vm.pike_vm.try_match(
                bck_code,
                &scanned_data[match_start..],
                &scanned_data[..match_start],
                flags.contains(SubPatternFlags::Wide),
                |bck_match_len| {
                    let range = match_start - bck_match_len
                        ..match_start + fwd_match_len;
                    if verify_full_word(scanned_data, &range, flags, None) {
                        f(range);
                    }
                    Action::Continue
                },
            );
        }
    } else {
        let range = match_start..match_start + fwd_match_len;
        if verify_full_word(scanned_data, &range, flags, None) {
            f(range);
        }
    }
}

/// Verifies that `pattern` actually matches in XORed form at `match_start`
/// within `scanned_data`.
///
/// Returns the XOR key if the match was confirmed, or [`None`] if otherwise.
fn verify_xor_match(
    pattern: &[u8],
    scanned_data: &[u8],
    match_start: usize,
    atom: &SubPatternAtom,
    flags: SubPatternFlags,
) -> Option<u8> {
    // Offset where the match should end (exclusive).
    let match_end = match_start + pattern.len();

    // The match can not end past the end of the scanned data.
    if match_end > scanned_data.len() {
        return None;
    }

    // The atom that matched is the result of XORing the pattern with some
    // key. The key can be obtained by XORing some byte in the atom with
    // the corresponding byte in the pattern.
    let key = atom.as_slice()[0] ^ pattern[atom.backtrack()];

    let match_range = match_start..match_end;

    if !verify_full_word(scanned_data, &match_range, flags, Some(key)) {
        return None;
    }

    let candidate = &scanned_data[match_start..match_end];

    if key == 0 {
        if pattern != candidate {
            return None;
        }
    } else if !xor_slices_eq(pattern, candidate, key) {
        return None;
    }

    Some(key)
}

#[inline]
fn xor_slices_eq(pattern: &[u8], candidate: &[u8], key: u8) -> bool {
    debug_assert_eq!(pattern.len(), candidate.len());

    if pattern.len() < 8 {
        let key_word = u32::from_ne_bytes([key; 4]);
        let (pattern_chunks, pattern_remainder) = pattern.as_chunks::<4>();
        let (candidate_chunks, candidate_remainder) =
            candidate.as_chunks::<4>();

        for (pattern, candidate) in pattern_chunks.iter().zip(candidate_chunks)
        {
            let pattern = u32::from_ne_bytes(*pattern);
            let candidate = u32::from_ne_bytes(*candidate);
            if pattern != candidate ^ key_word {
                return false;
            }
        }

        return pattern_remainder
            .iter()
            .zip(candidate_remainder)
            .all(|(pattern, candidate)| *pattern == (*candidate ^ key));
    }

    let key_word = u64::from_ne_bytes([key; 8]);
    let (pattern_chunks, pattern_remainder) = pattern.as_chunks::<8>();
    let (candidate_chunks, candidate_remainder) = candidate.as_chunks::<8>();

    for (pattern, candidate) in pattern_chunks.iter().zip(candidate_chunks) {
        let pattern = u64::from_ne_bytes(*pattern);
        let candidate = u64::from_ne_bytes(*candidate);
        if pattern != candidate ^ key_word {
            return false;
        }
    }

    pattern_remainder
        .iter()
        .zip(candidate_remainder)
        .all(|(pattern, candidate)| *pattern == (*candidate ^ key))
}

/// Verifies that `pattern` actually matches in base64 form at `match_start`
/// within `scanned_data`.
///
/// Returns the range where the match was found or [`None`] if otherwise.
fn verify_base64_match(
    pattern: &[u8],
    scanned_data: &[u8],
    padding: usize,
    match_start: usize,
    base64_engine: &base64::engine::GeneralPurpose,
    wide: bool,
) -> Option<Range<usize>> {
    // The pattern is passed to this function in its original form, before
    // being encoded as base64. Compute the size of the pattern once it is
    // encoded as base64.
    let len = base64::encoded_len(pattern.len(), false)?;

    // A portion of the pattern in base64 form was found at `match_start`,
    // but decoding the base64 string starting at that offset is not ok
    // because some characters may have been removed from both the left
    // and the right sides of the base64 string that has been found. For
    // example, for the pattern "foobar" one of the base64 patterns that
    // are searched for is "Zvb2Jhc", but once this pattern is found in
    // the scanned data we can't simply decode that string and expect
    // to find "foobar" in the decoded data.
    //
    // What we must do is use two more characters from the left, and one
    // more from the right of "Zvb2Jhc", like for example "eGZvb2Jhcg",
    // which is decoded as "xfoobar". The actual number of additional
    // characters that must be used from the left and right of the pattern
    // found depends on the padding and the rest of dividing the pattern's
    // length by 4. The table below covers all possible cases using the
    // plain text patterns "foobar", "fooba" and "foob".
    //
    // padding          base64                      len (mod 4)
    //    0   foobar    Zm9vYmFy    len(b64(foobar))  8 (0)  [Zm9vYmFy]
    //    0   fooba     Zm9vYmE     len(b64(fooba))   7 (3)  [Zm9vYm]E
    //    0   foob      Zm9vYg      len(b64(foob))    6 (2)  [Zm9vY]g
    //
    //    1   xfoobar   eGZvb2Jhcg  len(b64(foobar))  8 (0)  eG[Zvb2Jhc]g
    //    1   xfooba    eGZvb2Jh    len(b64(fooba))   7 (3)  eG[Zvb2Jh]
    //    1   xfoob     eGZvb2I     len(b64(foob))    6 (2)  eG[Zvb2]I
    //
    //    2   xxfoobar  eHhmb29iYXI len(b64(foobar))  8 (0)  eHh[mb29iYX]I
    //    2   xxfooba   eHhmb29iYQ  len(b64(fooba))   7 (3)  eHh[mb29iY]Q
    //    2   xxfoob    eHhmb29i    len(b64(foob))    6 (2)  eHh[mb29i]
    //
    // In the rightmost column the portion of the base64 pattern that is
    // searched using the Aho-Corasick algorithm is enclosed in [].
    let (mut decode_start_delta, mut decode_len, mut match_len) = match padding
    {
        0 => match len % 4 {
            0 => (0, len, len),
            2 => (0, len + 2, len - 1),
            3 => (0, len + 1, len - 1),
            _ => unreachable!(),
        },
        1 => match len % 4 {
            0 => (2, len + 4, len - 1),
            2 => (2, len + 2, len - 2),
            3 => (2, len + 1, len - 1),
            _ => unreachable!(),
        },
        2 => match len % 4 {
            0 => (3, len + 4, len - 1),
            2 => (3, len + 2, len - 1),
            3 => (3, len + 5, len - 1),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };

    // In wide mode each base64 character is two bytes long, adjust
    // decode_start_delta and lengths accordingly.
    if wide {
        decode_start_delta *= 2;
        decode_len *= 2;
        match_len *= 2;
    }

    // decode_range is the range within the scanned data that we are going
    // to decode as base64. It starts at match_start - decode_start_delta,
    // but if match_start < decode_start_delta this is not a real match.
    let mut decode_range = if let (decode_start, false) =
        match_start.overflowing_sub(decode_start_delta)
    {
        decode_start..decode_start + decode_len
    } else {
        return None;
    };

    // If the end of decode_range is past the end of the scanned data
    // truncate it to scanned_data_len.
    if decode_range.end > scanned_data.len() {
        decode_range.end = scanned_data.len();
    }

    let mut ascii_storage: SmallVec<[u8; 256]> = SmallVec::new();

    let encoded = if wide {
        // Collect the ASCII characters at even positions and make sure
        // that bytes at odd positions are zeroes.
        for (i, b) in scanned_data[decode_range].iter().enumerate() {
            if i.is_multiple_of(2) {
                // Padding (=) is not added to ASCII string.
                if *b != b'=' {
                    ascii_storage.push(*b)
                }
            } else if *b != 0 {
                return None;
            }
        }
        ascii_storage.as_slice()
    } else {
        let s = &scanned_data[decode_range];

        // Strip padding if present.
        if s.ends_with_str(b"==") {
            &s[0..s.len().saturating_sub(2)]
        } else if s.ends_with_str(b"=") {
            &s[0..s.len().saturating_sub(1)]
        } else {
            s
        }
    };

    let mut decoded: SmallVec<[u8; 256]> =
        smallvec::smallvec![0; base64::decoded_len_estimate(encoded.len())];

    let decoded_len =
        base64_engine.decode_slice(encoded, &mut decoded).ok()?;

    decoded.truncate(decoded_len);

    // If the decoding was successful, ignore the padding and compare to the
    // expected pattern.
    let decoded_pattern = decoded.get(padding..padding + pattern.len())?;

    if pattern.eq(decoded_pattern) {
        Some(match_start..match_start + match_len)
    } else {
        None
    }
}

fn handle_sub_pattern_match(
    tracker: &mut MatchTracker,
    wasm_state: &mut WasmState,
    sub_pattern_id: SubPatternId,
    sub_pattern: &SubPattern,
    pattern_id: PatternId,
    match_: Match,
) {
    match sub_pattern {
        SubPattern::Literal { .. }
        | SubPattern::Xor { .. }
        | SubPattern::Base64 { .. }
        | SubPattern::Base64Wide { .. }
        | SubPattern::CustomBase64 { .. }
        | SubPattern::CustomBase64Wide { .. } => {
            track_pattern_match(
                tracker, wasm_state, pattern_id, match_, false,
            );
        }
        SubPattern::Regexp { flags, .. } => {
            track_pattern_match(
                tracker,
                wasm_state,
                pattern_id,
                match_,
                flags.contains(SubPatternFlags::GreedyRegexp),
            );
        }
        SubPattern::LiteralChainHead { .. }
        | SubPattern::RegexpChainHead { .. } => tracker
            .unconfirmed_matches
            .entry(sub_pattern_id)
            .or_default()
            .push(UnconfirmedMatch { range: match_.range, chain_length: 0 }),
        SubPattern::LiteralChainTail { chained_to, gap, flags, .. }
        | SubPattern::RegexpChainTail { chained_to, gap, flags, .. } => {
            if within_valid_distance(
                tracker,
                *chained_to,
                match_.range.start,
                gap,
            ) {
                if flags.contains(SubPatternFlags::LastInChain) {
                    verify_chain_of_matches(
                        tracker,
                        wasm_state,
                        pattern_id,
                        sub_pattern_id,
                        match_,
                    );
                } else {
                    tracker
                        .unconfirmed_matches
                        .entry(sub_pattern_id)
                        .or_default()
                        .push(UnconfirmedMatch {
                            range: match_.range,
                            chain_length: 0,
                        });
                }
            }
        }
    }
}

fn track_pattern_match(
    tracker: &mut MatchTracker,
    wasm_state: &mut WasmState,
    pattern_id: PatternId,
    match_: Match,
    replace_if_longer: bool,
) {
    let wasm_store = wasm_state.store_mut();
    let mem = wasm_state.main_memory.unwrap().data_mut(wasm_store);
    let num_rules = tracker.compiled_rules.num_rules();
    let num_patterns = tracker.compiled_rules.num_patterns();

    let base = MATCHING_RULES_BITMAP_BASE as usize + num_rules.div_ceil(8);
    let bits = BitSlice::<u8, Lsb0>::from_slice_mut(
        &mut mem[base..base + num_patterns.div_ceil(8)],
    );

    bits.set(pattern_id.into(), true);

    if !tracker.pattern_matches.add(pattern_id, match_, replace_if_longer) {
        tracker.limit_reached.insert(pattern_id);
    }
}

fn within_valid_distance(
    tracker: &MatchTracker,
    chained_to: SubPatternId,
    match_start: usize,
    gap: &ChainedPatternGap,
) -> bool {
    if let Some(unconfirmed_matches) =
        tracker.unconfirmed_matches.get(&chained_to)
    {
        for m in unconfirmed_matches {
            match gap {
                ChainedPatternGap::Bounded(gap) => {
                    let min_gap = *gap.start() as usize;
                    let max_gap = *gap.end() as usize;
                    if (m.range.end + min_gap..=m.range.end + max_gap)
                        .contains(&match_start)
                    {
                        return true;
                    }
                }
                ChainedPatternGap::Unbounded(gap) => {
                    let min_gap = gap.start as usize;
                    if (m.range.start + min_gap..).contains(&match_start) {
                        return true;
                    }
                }
            };
        }
    }

    false
}

fn custom_base64_engine(
    cache: &mut Vec<(u32, base64::engine::GeneralPurpose)>,
    alphabet_id: u32,
    build_engine: impl FnOnce() -> base64::engine::GeneralPurpose,
) -> &base64::engine::GeneralPurpose {
    // Custom alphabets are uncommon and usually few per ruleset. A small Vec
    // avoids rebuilding decode tables in the hot path without adding hash-map
    // overhead to every candidate verification.
    let cached_index = cache.iter().position(|(id, _)| *id == alphabet_id);
    if let Some(index) = cached_index {
        return &cache[index].1;
    }

    cache.push((alphabet_id, build_engine()));
    &cache.last().unwrap().1
}

/// Virtual Machines used for evaluating regular expressions.
///
/// [`PikeVM`] allows executing all regular expressions, but it's slower.
/// [`FastVM`] is faster, but can execute only a subset of the regular
/// expressions, particularly those derived from hex patterns.
pub(crate) struct VM<'r> {
    pike_vm: PikeVM<'r>,
    fast_vm: FastVM<'r>,
}

/// A runtime object is a struct, array, map or string used during the
/// evaluation of a rule condition. Instances of these types can't cross the
/// WASM-Rust boundary, as integers and floats can do. Therefore, they are
/// stored in a hash map in [`ScanContext`], using a [`RuntimeObjectHandler`]
/// as the key that identifies each object. Handlers are actually 64-bits
/// integers that can cross the WASM-Rust boundary, and used to retrieve the
/// original object from [`ScanContext`].
pub(crate) enum RuntimeObject {
    Struct(Rc<Struct>),
    Array(Rc<Array>),
    Map(Rc<Map>),
    String(Rc<BString>),
}

impl RuntimeObject {
    pub fn as_struct(&self) -> Rc<Struct> {
        if let Self::Struct(s) = self {
            s.clone()
        } else {
            panic!(
                "calling `as_struct` in a RuntimeObject that is not a struct"
            )
        }
    }

    pub fn as_array(&self) -> Rc<Array> {
        if let Self::Array(a) = self {
            a.clone()
        } else {
            panic!(
                "calling `as_array` in a RuntimeObject that is not an array"
            )
        }
    }

    pub fn as_map(&self) -> Rc<Map> {
        if let Self::Map(m) = self {
            m.clone()
        } else {
            panic!("calling `as_map` in a RuntimeObject that is not a map")
        }
    }
}

/// A runtime object handle is an opaque integer value that identifies a
/// runtime object.
#[derive(Copy, Clone, Hash, Eq, PartialEq, Default)]
pub(crate) struct RuntimeObjectHandle(i64);

impl RuntimeObjectHandle {
    pub(crate) const NULL: Self = RuntimeObjectHandle(-1);
}

impl From<RuntimeObjectHandle> for i64 {
    fn from(value: RuntimeObjectHandle) -> Self {
        value.0
    }
}

impl From<i64> for RuntimeObjectHandle {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

pub fn create_wasm_store_and_ctx<'r>(
    rules: &'r Rules,
) -> Pin<Box<Store<ScanContext<'static, 'static>>>> {
    let num_rules = rules.num_rules() as u32;
    let num_patterns = rules.num_patterns() as u32;

    let ctx = ScanContext {
        runtime_objects: IndexMap::new(),
        compiled_rules: rules,
        console_log: None,
        current_struct: None,
        scan_timeout: None,
        match_context_size: 0,
        scan_state: ScanState::Idle,
        root_struct: rules.globals().make_root(),
        matching_rules: Vec::new(),
        matching_rules_per_ns: IndexMap::new(),
        num_matching_private_rules: 0,
        num_non_matching_private_rules: 0,
        wasm: WasmState {
            module: MaybeUninit::uninit(),
            main_memory: None,
            main_func: None,
            filesize: None,
            pattern_search_done: None,
            store: NonNull::dangling(),
        },
        module_outputs: FxHashMap::default(),
        user_provided_module_outputs: FxHashMap::default(),
        tracker: MatchTracker {
            pattern_matches: PatternMatches::new(),
            unconfirmed_matches: FxHashMap::default(),
            limit_reached: FxHashSet::default(),
            compiled_rules: rules,
        },
        deadline: 0,
        regexp_cache: RefCell::new(FxHashMap::default()),
        vm: VM {
            pike_vm: PikeVM::new(rules.re_code()),
            fast_vm: FastVM::new(rules.re_code()),
        },
        custom_base64_engine_cache: Vec::new(),
        #[cfg(feature = "rules-profiling")]
        time_spent_in_pattern: FxHashMap::default(),
        #[cfg(feature = "rules-profiling")]
        time_spent_in_rule: vec![0; num_rules as usize],
        #[cfg(feature = "rules-profiling")]
        rule_execution_start_time: 0,
        #[cfg(feature = "rules-profiling")]
        last_executed_rule: None,
        #[cfg(any(feature = "rules-profiling", feature = "logging"))]
        clock: quanta::Clock::new(),
    };

    // The ScanContext structure belongs to the WASM store, but at the same
    // time the context must have a reference to the store because it is
    // required for accessing the WASM memory from code that only has a
    // reference to ScanContext. This kind of circular data structures are
    // not natural to Rust, and they can be achieved either by using unsafe
    // pointers, or by using Rc::Weak. In this case we are storing a pointer
    // to the store in ScanContext. The store is put into a pinned box in order
    // to make sure that it doesn't move from its original memory address and
    // the pointer remains valid.
    //
    // Also, the `Store` type requires a type T that is static, therefore
    // we are forced to transmute the ScanContext<'r> into ScanContext<'static>.
    // This is safe to do because the Store only lives for the time that
    // the scanner lives, and 'r is the lifetime for the rules passed to
    // the scanner, which are guaranteed to outlive the scanner.
    let mut wasm_store = Box::pin(Store::new(wasm::get_engine(), unsafe {
        transmute::<ScanContext<'r, '_>, ScanContext<'static, 'static>>(ctx)
    }));

    // Initialize the ScanContext.wasm.store pointer that was initially
    // dangling.
    wasm_store.data_mut().wasm.store =
        NonNull::from(wasm_store.as_ref().deref());

    // Global variable that will hold the value for `filesize`. This is
    // initialized to -1 (which means undefined) because the file size
    // is not known until some data is scanned.
    let filesize = Global::new(
        wasm_store.as_context_mut(),
        GlobalType::new(ValType::I64, Mutability::Var),
        Val::I64(-1),
    )
    .unwrap();

    // Global variable that is set to `true` when the Aho-Corasick pattern
    // search phase has been executed.
    let pattern_search_done = Global::new(
        wasm_store.as_context_mut(),
        GlobalType::new(ValType::I32, Mutability::Var),
        Val::I32(0),
    )
    .unwrap();

    // Compute the base offset for the bitmap that contains matching
    // information for patterns. This bitmap has 1 bit per pattern, the
    // N-th bit is set if pattern with PatternId = N matched. The bitmap
    // starts right after the bitmap that contains matching information
    // for rules.
    let matching_patterns_bitmap_base =
        MATCHING_RULES_BITMAP_BASE as u32 + num_rules.div_ceil(8);

    // Compute the required memory size in 64KB pages.
    let mem_size = u32::div_ceil(
        matching_patterns_bitmap_base + num_patterns.div_ceil(8),
        65536,
    );

    let matching_patterns_bitmap_base = Global::new(
        wasm_store.as_context_mut(),
        GlobalType::new(ValType::I32, Mutability::Const),
        Val::I32(matching_patterns_bitmap_base as i32),
    )
    .unwrap();

    // Create module's main memory.
    let main_memory = wasm::runtime::Memory::new(
        wasm_store.as_context_mut(),
        MemoryType::new(mem_size, Some(mem_size)),
    )
    .unwrap();

    // Instantiate the module. This takes the wasm code provided by the
    // `wasm_mod` function and links its imported functions with the
    // implementations that YARA provides.
    let wasm_instance = wasm::new_linker()
        .define(wasm_store.as_context(), "yara_x", "filesize", filesize)
        .unwrap()
        .define(
            wasm_store.as_context(),
            "yara_x",
            "pattern_search_done",
            pattern_search_done,
        )
        .unwrap()
        .define(
            wasm_store.as_context(),
            "yara_x",
            "matching_patterns_bitmap_base",
            matching_patterns_bitmap_base,
        )
        .unwrap()
        .define(wasm_store.as_context(), "yara_x", "main_memory", main_memory)
        .unwrap()
        .instantiate(wasm_store.as_context_mut(), rules.wasm_mod())
        .unwrap();

    // Obtain a reference to the "main" function exported by the module.
    let main_fn = wasm_instance
        .get_typed_func::<(), i32>(wasm_store.as_context_mut(), "main")
        .unwrap();

    let ctx = wasm_store.data_mut();

    ctx.wasm.module = MaybeUninit::new(wasm_instance);
    ctx.wasm.main_memory = Some(main_memory);
    ctx.wasm.main_func = Some(main_fn);
    ctx.wasm.filesize = Some(filesize);
    ctx.wasm.pattern_search_done = Some(pattern_search_done);

    wasm_store
}
