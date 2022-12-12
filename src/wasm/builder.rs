use walrus::ValType::{Externref, F64, I32, I64};

use super::WasmSymbols;

/// Builds the WebAssembly module for a set of compiled rules.
pub(crate) struct ModuleBuilder {
    module: walrus::Module,
    wasm_symbols: WasmSymbols,
    main_fn: walrus::FunctionBuilder,
}

/// Helper macro that adds imports to a module.
///
/// # Example
///
/// This add an import for a function named `my_function`, that receives an
/// `i64` and returns an `Externref`.
///
/// ```ignore
/// import!(module, my_function, [I64], [Externref]);
/// ```
macro_rules! import {
    ($module:ident, $fn_name:ident, [$( $arg:ident ),*], [$( $result:ident ),*] ) => {
        let ty = $module.types.add(&[$( $arg ),*], &[$( $result ),*]);
        let ($fn_name, _) =
            $module.add_import_func("yr", stringify!($fn_name), ty);
    };
}

macro_rules! global {
    ($module:ident, $name:ident, $ty:ident ) => {
        let ($name, _) =
            $module.add_import_global("yr", stringify!($name), $ty, true);
    };
}

macro_rules! memory {
    ($module:ident, $name:ident ) => {
        let ($name, _) =
            $module.add_import_memory("yr", stringify!($name), true, 1, None);
    };
}

impl ModuleBuilder {
    /// Module's memory size in pages. Page size is 64KB.
    pub(crate) const MODULE_MEMORY_SIZE: u32 = 1;

    /// Creates a new module builder.
    pub fn new() -> Self {
        let config = walrus::ModuleConfig::new();
        let mut module = walrus::Module::with_config(config);

        memory!(module, rules_matching_bitmap);
        memory!(module, patterns_matching_bitmap);

        global!(module, filesize, I64);

        import!(module, rule_match, [I32], []);
        import!(module, is_pat_match, [I32], [I32]);
        import!(module, is_pat_match_at, [I32, I64], [I32]);
        import!(module, is_pat_match_in, [I32, I64, I64], [I32]);
        import!(module, literal_to_ref, [I64], [Externref]);

        import!(module, str_eq, [Externref, Externref], [I32]);
        import!(module, str_ne, [Externref, Externref], [I32]);
        import!(module, str_gt, [Externref, Externref], [I32]);
        import!(module, str_lt, [Externref, Externref], [I32]);
        import!(module, str_ge, [Externref, Externref], [I32]);
        import!(module, str_le, [Externref, Externref], [I32]);

        import!(module, str_contains, [Externref, Externref], [I32]);
        import!(module, str_icontains, [Externref, Externref], [I32]);
        import!(module, str_startswith, [Externref, Externref], [I32]);
        import!(module, str_endswith, [Externref, Externref], [I32]);
        import!(module, str_istartswith, [Externref, Externref], [I32]);
        import!(module, str_iendswith, [Externref, Externref], [I32]);
        import!(module, str_iequals, [Externref, Externref], [I32]);
        import!(module, str_len, [Externref], [I64]);

        import!(module, symbol_lookup_integer, [I64], [I64, I32]);
        import!(module, symbol_lookup_float, [I64], [F64, I32]);
        import!(module, symbol_lookup_bool, [I64], [I32, I32]);
        import!(module, symbol_lookup_string, [I64], [Externref]);
        import!(module, symbol_lookup_array, [I64], []);
        import!(module, symbol_lookup_struct, [I64], []);
        import!(module, symbol_lookup_map, [I64], []);

        import!(module, array_lookup_integer, [I64], [I64, I32]);
        import!(module, map_lookup_integer, [Externref], [I64, I32]);

        let wasm_symbols = WasmSymbols {
            rules_matching_bitmap,
            patterns_matching_bitmap,
            rule_match,
            is_pat_match,
            is_pat_match_at,
            is_pat_match_in,
            literal_to_ref,
            symbol_lookup_integer,
            symbol_lookup_float,
            symbol_lookup_bool,
            symbol_lookup_string,
            symbol_lookup_struct,
            symbol_lookup_array,
            symbol_lookup_map,
            array_lookup_integer,
            map_lookup_integer,
            str_eq,
            str_ne,
            str_lt,
            str_gt,
            str_le,
            str_ge,
            str_contains,
            str_startswith,
            str_endswith,
            str_icontains,
            str_istartswith,
            str_iendswith,
            str_iequals,
            str_len,
            filesize,
            vars_stack: module.memories.add_local(
                false,                          // not shared with host.
                Self::MODULE_MEMORY_SIZE,       // initial size 64KB
                Some(Self::MODULE_MEMORY_SIZE), // maximum size 64KB
            ),
            i64_tmp: module.locals.add(I64),
            i32_tmp: module.locals.add(I32),
            ref_tmp: module.locals.add(Externref),
        };

        let main_fn =
            walrus::FunctionBuilder::new(&mut module.types, &[], &[]);

        Self { module, wasm_symbols, main_fn }
    }

    /// Returns a [`InstrSeqBuilder`] for the module's main function.
    ///
    /// This allows adding code to the module's `main` function.
    pub fn main_fn(&mut self) -> walrus::InstrSeqBuilder {
        self.main_fn.func_body()
    }

    /// Returns the symbols imported by the module.
    pub fn wasm_symbols(&self) -> WasmSymbols {
        self.wasm_symbols.clone()
    }

    /// Builds the module and consumes the builder.
    pub fn build(mut self) -> walrus::Module {
        let main_fn = self.main_fn.finish(Vec::new(), &mut self.module.funcs);
        self.module.exports.add("main", main_fn);
        self.module
    }
}
