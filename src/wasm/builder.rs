use walrus::ValType::{F64, I32, I64};

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
    ($module:ident, $fn_name:ident, [$( $arg:ident ),*], maybe_undef()) => {
        let ty = $module.types.add(&[$( $arg ),*], &[I32]);
        let ($fn_name, _) =
            $module.add_import_func("yr", stringify!($fn_name), ty);
    };
    ($module:ident, $fn_name:ident, [$( $arg:ident ),*], maybe_undef($ty:ident)) => {
        let ty = $module.types.add(&[$( $arg ),*], &[$ty, I32]);
        let ($fn_name, _) =
            $module.add_import_func("yr", stringify!($fn_name), ty);
    };
}

macro_rules! global_var {
    ($module:ident, $name:ident, $ty:ident) => {
        let ($name, _) =
            $module.add_import_global("yr", stringify!($name), $ty, true);
    };
}

macro_rules! global_const {
    ($module:ident, $name:ident, $ty:ident) => {
        let ($name, _) =
            $module.add_import_global("yr", stringify!($name), $ty, false);
    };
}

impl ModuleBuilder {
    /// Creates a new module builder.
    pub fn new() -> Self {
        let config = walrus::ModuleConfig::new();
        let mut module = walrus::Module::with_config(config);

        global_const!(module, matching_patterns_bitmap_base, I32);
        global_var!(module, lookup_stack_top, I32);
        global_var!(module, lookup_start, I32);
        global_var!(module, filesize, I64);

        import!(module, rule_match, [I32], []);
        import!(module, is_pat_match_at, [I32, I64], [I32]);
        import!(module, is_pat_match_in, [I32, I64, I64], [I32]);

        import!(module, str_eq, [I64, I64], [I32]);
        import!(module, str_ne, [I64, I64], [I32]);
        import!(module, str_gt, [I64, I64], [I32]);
        import!(module, str_lt, [I64, I64], [I32]);
        import!(module, str_ge, [I64, I64], [I32]);
        import!(module, str_le, [I64, I64], [I32]);

        import!(module, str_contains, [I64, I64], [I32]);
        import!(module, str_icontains, [I64, I64], [I32]);
        import!(module, str_startswith, [I64, I64], [I32]);
        import!(module, str_endswith, [I64, I64], [I32]);
        import!(module, str_istartswith, [I64, I64], [I32]);
        import!(module, str_iendswith, [I64, I64], [I32]);

        import!(module, str_iequals, [I64, I64], [I32]);
        import!(module, str_len, [I64], [I64]);

        import!(module, array_len, [I32], [I64]);
        import!(module, map_len, [I32], [I64]);

        import!(module, lookup_integer, [], maybe_undef(I64));
        import!(module, lookup_float, [], maybe_undef(F64));
        import!(module, lookup_bool, [], maybe_undef(I32));
        import!(module, lookup_string, [], [I64]);
        import!(module, lookup_value, [I32], []);

        import!(module, array_lookup_integer, [I64, I32], maybe_undef(I64));
        import!(module, array_lookup_float, [I64, I32], maybe_undef(F64));
        import!(module, array_lookup_bool, [I64, I32], maybe_undef(I32));
        import!(module, array_lookup_string, [I64, I32], [I64]);
        import!(module, array_lookup_struct, [I64, I32], maybe_undef());

        import!(module, map_lookup_integer_integer, [I64], maybe_undef(I64));
        import!(module, map_lookup_string_integer, [I64], maybe_undef(I64));
        import!(module, map_lookup_integer_float, [I64], maybe_undef(F64));
        import!(module, map_lookup_string_float, [I64], maybe_undef(F64));
        import!(module, map_lookup_integer_bool, [I64], maybe_undef(I32));
        import!(module, map_lookup_string_bool, [I64], maybe_undef(I32));
        import!(module, map_lookup_integer_string, [I64], [I64]);
        import!(module, map_lookup_string_string, [I64], [I64]);
        import!(module, map_lookup_integer_struct, [I64], maybe_undef());
        import!(module, map_lookup_string_struct, [I64], maybe_undef());

        let (main_memory, _) =
            module.add_import_memory("yr", "main_memory", false, 1, None);

        let wasm_symbols = WasmSymbols {
            main_memory,
            matching_patterns_bitmap_base,
            rule_match,
            is_pat_match_at,
            is_pat_match_in,
            array_len,
            map_len,
            lookup_start,
            lookup_stack_top,
            lookup_integer,
            lookup_float,
            lookup_bool,
            lookup_string,
            lookup_value,
            array_lookup_integer,
            array_lookup_float,
            array_lookup_bool,
            array_lookup_string,
            array_lookup_struct,
            map_lookup_integer_integer,
            map_lookup_string_integer,
            map_lookup_integer_float,
            map_lookup_string_float,
            map_lookup_integer_bool,
            map_lookup_string_bool,
            map_lookup_integer_string,
            map_lookup_string_string,
            map_lookup_integer_struct,
            map_lookup_string_struct,
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
            i64_tmp: module.locals.add(I64),
            i32_tmp: module.locals.add(I32),
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
