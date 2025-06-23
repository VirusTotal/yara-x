use std::collections::HashMap;
#[cfg(feature = "rules-profiling")]
use std::ffi::CString;
use std::ffi::{c_char, c_void, CStr};
use std::slice;
use std::time::Duration;

use yara_x::errors::ScanError;
use yara_x::ScanOptions;

use crate::{
    _yrx_set_last_error, YRX_RESULT, YRX_RULE, YRX_RULES, YRX_RULE_CALLBACK,
};

/// A scanner that scans data with a set of compiled YARA rules.
pub struct YRX_SCANNER<'s, 'm> {
    inner: yara_x::Scanner<'s>,
    on_matching_rule: Option<(YRX_RULE_CALLBACK, *mut std::ffi::c_void)>,
    module_data: HashMap<&'m str, &'m [u8]>,
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
        inner: yara_x::Scanner::new(rules.inner()),
        on_matching_rule: None,
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

    let scan_results = scanner.inner.scan_with_options(data, options);

    if let Err(err) = scan_results {
        let result = match err {
            ScanError::Timeout => YRX_RESULT::YRX_SCAN_TIMEOUT,
            _ => YRX_RESULT::YRX_SCAN_ERROR,
        };
        _yrx_set_last_error(Some(err));
        return result;
    }

    let scan_results = scan_results.unwrap();

    if let Some((callback, user_data)) = scanner.on_matching_rule {
        for r in scan_results.matching_rules() {
            callback(&YRX_RULE::new(r), user_data);
        }
    }

    YRX_RESULT::YRX_SUCCESS
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

    let module_name = match CStr::from_ptr(name).to_str() {
        Ok(name) => name,
        Err(err) => {
            _yrx_set_last_error(Some(err));
            return YRX_RESULT::YRX_INVALID_UTF8;
        }
    };

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

    match scanner.inner.set_module_output_raw(module_name, data) {
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

    let name = match CStr::from_ptr(name).to_str() {
        Ok(name) => name,
        Err(err) => {
            _yrx_set_last_error(Some(err));
            return YRX_RESULT::YRX_INVALID_UTF8;
        }
    };

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::YRX_INVALID_ARGUMENT,
    };

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

    let ident = match CStr::from_ptr(ident).to_str() {
        Ok(ident) => ident,
        Err(err) => {
            _yrx_set_last_error(Some(err));
            return YRX_RESULT::YRX_INVALID_UTF8;
        }
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
    match CStr::from_ptr(value).to_str() {
        Ok(value) => yrx_scanner_set_global(scanner, ident, value),
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_INVALID_UTF8
        }
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
        slice::from_raw_parts(data, len)
    };
    Some(data)
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
/// [`YRX_RESULT::NOT_SUPPORTED`].
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
/// [`YRX_RESULT::NOT_SUPPORTED`].
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
