use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::{c_char, c_void, CStr};
use std::mem;
use std::time::Duration;

#[cfg(feature = "rules-profiling")]
use yara_x::ProfilingData;

use yara_x::errors::ScanError;
use yara_x::ScanOptions;

use crate::{
    _yrx_set_last_error, YRX_RESULT, YRX_RULE, YRX_RULES, YRX_RULE_CALLBACK,
};

enum InnerScanner<'r> {
    None,
    SingleBlock(yara_x::Scanner<'r>),
    MultiBlock(yara_x::blocks::Scanner<'r>),
}

impl<'r> InnerScanner<'r> {
    fn set_timeout(&mut self, duration: Duration) -> &mut Self {
        match self {
            InnerScanner::SingleBlock(s) => {
                s.set_timeout(duration);
            }
            InnerScanner::MultiBlock(s) => {
                s.set_timeout(duration);
            }
            InnerScanner::None => unreachable!(),
        }
        self
    }

    fn make_multi_block(&mut self) -> &mut yara_x::blocks::Scanner<'r> {
        // Already a multi-block scanner, nothing else to do.
        if let Self::MultiBlock(s) = self {
            return s;
        }
        // It's currently a single-block scanner, replace it with a multi-block
        // scanner.
        if let Self::SingleBlock(s) = mem::replace(self, InnerScanner::None) {
            *self = InnerScanner::MultiBlock(s.into());
        }
        // At this point it must be a multi-block scanner.
        match self {
            InnerScanner::MultiBlock(s) => s,
            _ => unreachable!(),
        }
    }

    fn set_global<T>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<&mut Self, yara_x::errors::VariableError>
    where
        T: TryInto<yara_x::Variable, Error = yara_x::errors::VariableError>,
    {
        match self {
            InnerScanner::SingleBlock(s) => {
                s.set_global(ident, value)?;
            }
            InnerScanner::MultiBlock(s) => {
                s.set_global(ident, value)?;
            }
            InnerScanner::None => unreachable!(),
        }
        Ok(self)
    }

    #[cfg(feature = "rules-profiling")]
    fn slowest_rules(&self, n: usize) -> Vec<ProfilingData<'_>> {
        match self {
            InnerScanner::SingleBlock(s) => s.slowest_rules(n),
            InnerScanner::MultiBlock(s) => s.slowest_rules(n),
            InnerScanner::None => unreachable!(),
        }
    }

    #[cfg(feature = "rules-profiling")]
    fn clear_profiling_data(&mut self) {
        match self {
            InnerScanner::SingleBlock(s) => s.clear_profiling_data(),
            InnerScanner::MultiBlock(s) => s.clear_profiling_data(),
            InnerScanner::None => unreachable!(),
        }
    }
}

/// A scanner that scans data with a set of compiled YARA rules.
pub struct YRX_SCANNER<'r, 'm> {
    inner: InnerScanner<'r>,
    on_matching_rule: Option<(YRX_RULE_CALLBACK, *mut c_void)>,
    on_console_log: Option<YRX_CONSOLE_CALLBACK>,
    module_data: HashMap<&'m str, &'m [u8]>,
}

impl<'r, 'm> YRX_SCANNER<'r, 'm> {
    fn set_console_log(&mut self) -> &mut Self {
        let callback = self.on_console_log.unwrap();
        let c = |message: String| {
            //println!("CLOSURE {message}");
            let msg = CString::new(message).unwrap();
            callback(msg.as_ptr());
        };
        match &mut self.inner {
            InnerScanner::SingleBlock(s) => {
                s.console_log(c);
            }
            InnerScanner::MultiBlock(s) => {
                s.console_log(c);
            }
            InnerScanner::None => unreachable!(),
        }
        self
    }
}

/// Creates a [`YRX_SCANNER`] object that can be used for scanning data with
/// the provided [`YRX_RULES`].
///
/// It's ok to pass the same [`YRX_RULES`] to multiple scanners, and use each
/// scanner from a different thread. The scanner can be used as many times as
/// you want, and it must be destroyed with [`yrx_scanner_destroy`]. Also, the
/// scanner is valid as long as the rules are not destroyed, so, always destroy
/// the [`YRX_SCANNER`] object before the [`YRX_RULES`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_create(
    rules: *const YRX_RULES,
    scanner: &mut *mut YRX_SCANNER,
) -> YRX_RESULT {
    let rules = if let Some(rules) = rules.as_ref() {
        rules
    } else {
        return YRX_RESULT::YRX_INVALID_ARGUMENT;
    };

    *scanner = Box::into_raw(Box::new(YRX_SCANNER {
        inner: InnerScanner::SingleBlock(yara_x::Scanner::new(rules.inner())),
        on_matching_rule: None,
        on_console_log: None,
        module_data: HashMap::new(),
    }));

    YRX_RESULT::YRX_SUCCESS
}

/// Destroys a [`YRX_SCANNER`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_destroy(scanner: *mut YRX_SCANNER) {
    drop(Box::from_raw(scanner))
}

/// Sets a timeout (in seconds) for scan operations.
///
/// The scan functions will return a timeout error once the provided timeout
/// duration has elapsed. The scanner will make every effort to stop promptly
/// after the designated timeout duration. However, in some cases, particularly
/// with rules containing only a few patterns, the scanner could potentially
/// continue running for a longer period than the specified timeout.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_timeout(
    scanner: *mut YRX_SCANNER,
    timeout: u64,
) -> YRX_RESULT {
    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    scanner.inner.set_timeout(Duration::from_secs(timeout));

    YRX_RESULT::YRX_SUCCESS
}

/// Scans a data buffer.
///
/// `data` can be null as long as `len` is 0. In such cases its handled as
/// empty data. Some YARA rules (i.e: `rule dummy { condition: true }`) can
/// match even with empty data.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_scan(
    scanner: *mut YRX_SCANNER,
    data: *const u8,
    len: usize,
) -> YRX_RESULT {
    _yrx_set_last_error::<ScanError>(None);

    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    let options = scanner
        .module_data
        .drain()
        .fold(ScanOptions::new(), |acc, (module_name, meta)| {
            acc.set_module_metadata(module_name, meta)
        });

    let scan_results = match &mut scanner.inner {
        InnerScanner::SingleBlock(s) => s.scan_with_options(data, options),
        InnerScanner::MultiBlock(_) => return YRX_RESULT::YRX_INVALID_STATE,
        InnerScanner::None => unreachable!(),
    };

    match scan_results {
        Ok(results) => {
            if let Some((callback, user_data)) = scanner.on_matching_rule {
                for r in results.matching_rules() {
                    callback(&YRX_RULE::new(r), user_data);
                }
            }
            YRX_RESULT::YRX_SUCCESS
        }
        Err(ScanError::Timeout) => {
            _yrx_set_last_error(Some(ScanError::Timeout));
            YRX_RESULT::YRX_SCAN_TIMEOUT
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_SCAN_ERROR
        }
    }
}

/// Scans a file.
///
/// This function is similar to `yrx_scanner_scan`, but it receives a file
/// path instead of data to be scanned.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_scan_file(
    scanner: *mut YRX_SCANNER,
    path: *const c_char,
) -> YRX_RESULT {
    _yrx_set_last_error::<ScanError>(None);

    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    let path = match str_from_ptr(path) {
        Ok(path) => path,
        Err(err) => return err,
    };

    let options = scanner
        .module_data
        .drain()
        .fold(ScanOptions::new(), |acc, (module_name, meta)| {
            acc.set_module_metadata(module_name, meta)
        });

    let scan_results = match &mut scanner.inner {
        InnerScanner::SingleBlock(s) => {
            s.scan_file_with_options(path, options)
        }
        InnerScanner::MultiBlock(_) => return YRX_RESULT::YRX_INVALID_STATE,
        InnerScanner::None => unreachable!(),
    };

    match scan_results {
        Ok(results) => {
            if let Some((callback, user_data)) = scanner.on_matching_rule {
                for r in results.matching_rules() {
                    callback(&YRX_RULE::new(r), user_data);
                }
            }
            YRX_RESULT::YRX_SUCCESS
        }
        Err(ScanError::Timeout) => {
            _yrx_set_last_error(Some(ScanError::Timeout));
            YRX_RESULT::YRX_SCAN_TIMEOUT
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_SCAN_ERROR
        }
    }
}

/// Scans a block of data.
///
/// This function is designed for scenarios where the data to be scanned is not
/// available as a single contiguous block of memory, but rather arrives in
/// smaller, discrete blocks, allowing for incremental scanning.
///
/// Each call to this function scans a block of data. The `base` argument
/// specifies the offset of the current block within the overall data being
/// scanned. In most cases you will want to call this function multiple times,
/// providing a different block on each call.
///
/// Once this function is called for a scanner, it enters block scanning mode
/// and any subsequent call to [`yrx_scanner_scan`] will fail with
/// [`YRX_RESULT::YRX_INVALID_STATE`]. Once the scanner is in block scanning
/// mode it can be used in that mode only.
///
/// When all blocks have been scanned, you must call [`yrx_scanner_finish`].
///
/// # Limitations of Block Scanning
///
/// Block scanning works by analyzing data in chunks rather than as a whole
/// file. This makes it useful for streaming or memory-constrained scenarios,
/// but it comes with important limitations compared to standard scanning:
///
/// 1) Modules won't work. Parsers for structured formats (e.g., PE, ELF)
///    require access to the entire file and cannot be applied in block
///    scanning mode.
/// 2) Other modules like `hash` won't work either, as they require access to
///    all the scanned data during the evaluation of the rule's condition,
///    something that can't be guaranteed in block scanning mode. The hash
///    functions will return `undefined` when used in a multi-block context.
/// 3) Built-in functions like `uint8`, `uint16`, `uint32`, etc., have the
///    same limitation. They also return `undefined` in block scanning mode.
/// 4) The `filesize` keyword returns `undefined` in block scanning mode.
/// 5) Patterns won't match across block boundaries. Every match will be
///    completely contained within one of the blocks.
///
/// All these limitations imply that in block scanning mode you should only
/// use rules that rely on text, hex or regex patterns.
///
/// # Data Consistency in Overlapping Blocks
///
/// When [`yrx_scanner_scan_block`] is invoked multiple times with different
/// blocks that may overlap, the user is responsible for ensuring data
/// consistency. This means that if the same region of the original data is
/// present in two or more overlapping blocks, the content of that region must
/// be identical across all calls to `scan`.
///
/// Generally speaking, the scanner does not verify this consistency and
/// assumes the user provides accurate and consistent data. In debug releases
/// the scanner may try to verify this consistency, but only when some pattern
/// matches in the overlapping region.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_scan_block(
    scanner: *mut YRX_SCANNER,
    base: usize,
    data: *const u8,
    len: usize,
) -> YRX_RESULT {
    _yrx_set_last_error::<ScanError>(None);

    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    match scanner.inner.make_multi_block().scan(base, data) {
        Ok(_) => YRX_RESULT::YRX_SUCCESS,
        Err(ScanError::Timeout) => {
            _yrx_set_last_error(Some(ScanError::Timeout));
            YRX_RESULT::YRX_SCAN_TIMEOUT
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_SCAN_ERROR
        }
    }
}

/// Finalizes the scan of a set of memory blocks.
///
/// This function must be used in conjunction with [`yrx_scanner_scan_block`]
/// when scanning data in blocks. After all data blocks have been scanned, this
/// functions evaluates the conditions of the YARA rules and produces the final
/// scan results.
///
/// After this function returns, the scanner is ready to be used again for
/// scanning a new set of memory blocks. However, the scanner remains in block
/// scanning mode and can't be used for normal scanning.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_finish(
    scanner: *mut YRX_SCANNER,
) -> YRX_RESULT {
    _yrx_set_last_error::<ScanError>(None);

    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    match scanner.inner.make_multi_block().finish() {
        Ok(results) => {
            if let Some((callback, user_data)) = scanner.on_matching_rule {
                for r in results.matching_rules() {
                    callback(&YRX_RULE::new(r), user_data);
                }
            }
            YRX_RESULT::YRX_SUCCESS
        }
        Err(ScanError::Timeout) => {
            _yrx_set_last_error(Some(ScanError::Timeout));
            YRX_RESULT::YRX_SCAN_TIMEOUT
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_SCAN_ERROR
        }
    }
}

/// Sets a callback function that is called by the scanner for each rule that
/// matched during a scan.
///
/// The `user_data` pointer can be used to provide additional context to your
/// callback function. If the callback is not set, the scanner doesn't notify
/// about matching rules.
///
/// See [`YRX_RULE_CALLBACK`] for more details.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_on_matching_rule(
    scanner: *mut YRX_SCANNER,
    callback: YRX_RULE_CALLBACK,
    user_data: *mut std::ffi::c_void,
) -> YRX_RESULT {
    if let Some(scanner) = scanner.as_mut() {
        scanner.on_matching_rule = Some((callback, user_data));
        YRX_RESULT::YRX_SUCCESS
    } else {
        YRX_RESULT::YRX_INVALID_ARGUMENT
    }
}

/// Specifies the output data structure for a module.
///
/// Each YARA module generates an output consisting of a data structure that
/// contains information about the scanned file. This data structure is represented
/// by a Protocol Buffer. Typically, you won't need to provide this output data
/// yourself, as the YARA module automatically generates different outputs for
/// each file it scans.
///
/// However, there are two scenarios in which you may want to provide the output
/// for a module yourself:
///
/// 1) When the module does not produce any output on its own.
/// 2) When you already know the output of the module for the upcoming file to
///    be scanned, and you prefer to reuse this data instead of generating it
///    again.
///
/// Case 1) applies to certain modules lacking a main function, thus incapable of
/// producing any output on their own. For such modules, you must set the output
/// before scanning the associated data. Since the module's output typically varies
/// with each scanned file, you need to call [yrx_scanner_set_module_output] prior
/// to each invocation of [yrx_scanner_scan]. Once [yrx_scanner_scan] is executed,
/// the module's output is consumed and will be empty unless set again before the
/// subsequent call.
///
/// Case 2) applies when you have previously stored the module's output for certain
/// scanned data. In such cases, when rescanning the data, you can utilize this
/// function to supply the module's output, thereby preventing redundant computation
/// by the module. This optimization enhances performance by eliminating the need
/// for the module to reparse the scanned data.
///
/// The `name` argument is either a YARA module name (i.e: "pe", "elf", "dotnet",
/// etc.) or the fully-qualified name of the protobuf message associated to
/// the module. It must be a valid UTF-8 string.
///
/// If the scanner is in block scanning mode this function returns `YRX_INVALID_STATE`.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_module_output(
    scanner: *mut YRX_SCANNER,
    name: *const c_char,
    data: *const u8,
    len: usize,
) -> YRX_RESULT {
    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    let module_name = match str_from_ptr(name) {
        Ok(module_name) => module_name,
        Err(err) => return err,
    };

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    match &mut scanner.inner {
        InnerScanner::SingleBlock(scanner) => {
            match scanner.set_module_output_raw(module_name, data) {
                Ok(_) => {
                    _yrx_set_last_error::<ScanError>(None);
                    YRX_RESULT::YRX_SUCCESS
                }
                Err(err) => {
                    _yrx_set_last_error(Some(err));
                    YRX_RESULT::YRX_SCAN_ERROR
                }
            }
        }
        // This function produces an error if invoked while the scanner
        // is in block scanning mode.
        InnerScanner::MultiBlock(_) => YRX_RESULT::YRX_INVALID_STATE,
        InnerScanner::None => unreachable!(),
    }
}

/// Specifies metadata for a module.
///
/// Since the module's output typically varies with each scanned file, you need to
/// call [yrx_scanner_set_module_data] prior to each invocation of
/// [yrx_scanner_scan]. Once [yrx_scanner_scan] is executed, the module's metadata
/// is consumed and will be empty unless set again before the subsequent call.
///
/// The `name` argument is the name of a YARA module. It must be a valid UTF-8 string.
///
/// The `name` as well as `data` must be valid from the time they are used as arguments
/// of this function until the scan is executed.
///
/// If the scanner is in block scanning mode this function returns `YRX_INVALID_STATE`.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_module_data(
    scanner: *mut YRX_SCANNER,
    name: *const c_char,
    data: *const u8,
    len: usize,
) -> YRX_RESULT {
    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    let name = match str_from_ptr(name) {
        Ok(name) => name,
        Err(err) => return err,
    };

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    if matches!(scanner.inner, InnerScanner::MultiBlock(_)) {
        return YRX_RESULT::YRX_INVALID_STATE;
    }

    scanner.module_data.insert(name, data);

    YRX_RESULT::YRX_SUCCESS
}

unsafe extern "C" fn yrx_scanner_set_global<
    T: TryInto<yara_x::Variable, Error = yara_x::errors::VariableError>,
>(
    scanner: *mut YRX_SCANNER,
    ident: *const c_char,
    value: T,
) -> YRX_RESULT {
    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    let ident = match str_from_ptr(ident) {
        Ok(ident) => ident,
        Err(err) => return err,
    };

    match scanner.inner.set_global(ident, value) {
        Ok(_) => {
            _yrx_set_last_error::<ScanError>(None);
            YRX_RESULT::YRX_SUCCESS
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_VARIABLE_ERROR
        }
    }
}

/// Sets the value of a global variable of type string.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_global_str(
    scanner: *mut YRX_SCANNER,
    ident: *const c_char,
    value: *const c_char,
) -> YRX_RESULT {
    match str_from_ptr(value) {
        Ok(value) => yrx_scanner_set_global(scanner, ident, value),
        Err(err) => err,
    }
}

/// Sets the value of a global variable of type bool.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_global_bool(
    scanner: *mut YRX_SCANNER,
    ident: *const c_char,
    value: bool,
) -> YRX_RESULT {
    yrx_scanner_set_global(scanner, ident, value)
}

/// Sets the value of a global variable of type int.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_global_int(
    scanner: *mut YRX_SCANNER,
    ident: *const c_char,
    value: i64,
) -> YRX_RESULT {
    yrx_scanner_set_global(scanner, ident, value)
}

/// Sets the value of a global variable of type float.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_global_float(
    scanner: *mut YRX_SCANNER,
    ident: *const c_char,
    value: f64,
) -> YRX_RESULT {
    yrx_scanner_set_global(scanner, ident, value)
}

/// Sets the value of a global variable from a JSON-encoded string.
///
/// This is best for complex types like maps and arrays. For simple types
/// (e.g., booleans, integers, strings), prefer dedicated functions to avoid
/// the overhead of JSON deserialization.
///
/// The type of the JSON-encoded value must match the type of the variable
/// as it was defined.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_global_json(
    scanner: *mut YRX_SCANNER,
    ident: *const c_char,
    value: *const c_char,
) -> YRX_RESULT {
    let value = match str_from_ptr(value) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let value: serde_json::Value = match serde_json::from_str(value) {
        Ok(json_value) => json_value,
        Err(_) => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    yrx_scanner_set_global(scanner, ident, value)
}

/// Callback function used when a YARA rule calls the console module.
///
/// The callback function is invoked with a string representing the message
/// being logged. The function can print the message to stdout, append it to a
/// file, etc. If no callback is set these messages are ignored.
pub type YRX_CONSOLE_CALLBACK = extern "C" fn(message: *const c_char) -> ();

/// Sets the callback for console module.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_on_console_log(
    scanner: *mut YRX_SCANNER,
    callback: YRX_CONSOLE_CALLBACK,
) -> YRX_RESULT {
    let scanner = match scanner.as_mut() {
        Some(s) => s,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    scanner.on_console_log = Some(callback);
    scanner.set_console_log();

    YRX_RESULT::YRX_SUCCESS
}

/// Callback function passed to [`yrx_scanner_iter_slowest_rules`].
///
/// The callback function receives pointers to the namespace and rule name,
/// and two float numbers with the time spent by the rule matching patterns
/// and executing its condition. The pointers are valid as long as the callback
/// function is being executed, but will be freed after the callback returns.
///
/// The callback also receives a `user_data` pointer that can point to arbitrary
/// data owned by the user.
///
/// Requires the `rules-profiling` feature.
pub type YRX_SLOWEST_RULES_CALLBACK = extern "C" fn(
    namespace_: *const c_char,
    rule: *const c_char,
    pattern_matching_time: f64,
    condition_exec_time: f64,
    user_data: *mut c_void,
) -> ();

/// Iterates over the slowest N rules, calling the callback for each rule.
///
/// Requires the `rules-profiling` feature, otherwise returns
/// `YRX_RESULT::NOT_SUPPORTED`.
///
/// See [`YRX_SLOWEST_RULES_CALLBACK`] for more details.
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn yrx_scanner_iter_slowest_rules(
    scanner: *mut YRX_SCANNER,
    n: usize,
    callback: YRX_SLOWEST_RULES_CALLBACK,
    user_data: *mut c_void,
) -> YRX_RESULT {
    #[cfg(not(feature = "rules-profiling"))]
    return YRX_RESULT::YRX_NOT_SUPPORTED;

    #[cfg(feature = "rules-profiling")]
    {
        let scanner = match scanner.as_ref() {
            Some(s) => s,
            None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
        };

        for profiling_info in scanner.inner.slowest_rules(n) {
            let namespace = CString::new(profiling_info.namespace).unwrap();
            let rule = CString::new(profiling_info.rule).unwrap();

            callback(
                namespace.as_ptr(),
                rule.as_ptr(),
                profiling_info.pattern_matching_time.as_secs_f64(),
                profiling_info.condition_exec_time.as_secs_f64(),
                user_data,
            );
        }

        YRX_RESULT::YRX_SUCCESS
    }
}

/// Clears all accumulated profiling data.
///
/// This resets the profiling data collected during rule execution across
/// scanned files. Use this to start a new profiling session, ensuring the
/// results reflect only the data gathered after this method is called.
///
/// Requires the `rules-profiling` feature, otherwise returns
/// `YRX_RESULT::NOT_SUPPORTED`.
///
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn yrx_scanner_clear_profiling_data(
    scanner: *mut YRX_SCANNER,
) -> YRX_RESULT {
    #[cfg(not(feature = "rules-profiling"))]
    return YRX_RESULT::YRX_NOT_SUPPORTED;

    #[cfg(feature = "rules-profiling")]
    {
        match scanner.as_mut() {
            Some(s) => s.inner.clear_profiling_data(),
            None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
        };

        YRX_RESULT::YRX_SUCCESS
    }
}

unsafe fn slice_from_ptr_and_len<'a>(
    data: *const u8,
    len: usize,
) -> Option<&'a [u8]> {
    // `data` is allowed to be null as long as `len` is 0. That's equivalent
    // to an empty slice.
    if data.is_null() && len > 0 {
        return None;
    }
    let data = if data.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len)
    };
    Some(data)
}

unsafe fn str_from_ptr<'a>(s: *const c_char) -> Result<&'a str, YRX_RESULT> {
    match CStr::from_ptr(s).to_str() {
        Ok(s) => Ok(s),
        Err(err) => {
            _yrx_set_last_error(Some(err));
            Err(YRX_RESULT::YRX_INVALID_UTF8)
        }
    }
}
