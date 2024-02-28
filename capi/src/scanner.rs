use std::ffi::{c_char, CStr, CString};
use std::slice;
use std::time::Duration;
use yara_x::ScanError;

use crate::{LAST_ERROR, YRX_RESULT, YRX_RULE, YRX_RULES};

/// A scanner that scans data with a set of compiled YARA rules.
pub struct YRX_SCANNER<'s> {
    inner: yara_x::Scanner<'s>,
    on_matching_rule: Option<(YRX_ON_MATCHING_RULE, *mut std::ffi::c_void)>,
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
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    *scanner = Box::into_raw(Box::new(YRX_SCANNER {
        inner: yara_x::Scanner::new(&rules.0),
        on_matching_rule: None,
    }));

    YRX_RESULT::SUCCESS
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
pub unsafe extern "C" fn yrx_scanner_timeout(
    scanner: *mut YRX_SCANNER,
    timeout: u64,
) -> YRX_RESULT {
    if scanner.is_null() {
        return YRX_RESULT::INVALID_ARGUMENT;
    }

    let scanner = scanner.as_mut().unwrap();
    scanner.inner.timeout(Duration::from_secs(timeout));

    YRX_RESULT::SUCCESS
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
    if scanner.is_null() {
        return YRX_RESULT::INVALID_ARGUMENT;
    }

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::INVALID_ARGUMENT,
    };

    let scanner = scanner.as_mut().unwrap();
    let scan_results = scanner.inner.scan(data);

    if let Err(err) = scan_results {
        LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
        return match err {
            ScanError::Timeout => YRX_RESULT::SCAN_TIMEOUT,
            _ => YRX_RESULT::SCAN_ERROR,
        };
    }

    let scan_results = scan_results.unwrap();

    if let Some((callback, user_data)) = scanner.on_matching_rule {
        for r in scan_results.matching_rules() {
            let rule = YRX_RULE(r);
            callback(&rule as *const YRX_RULE, user_data);
        }
    }

    LAST_ERROR.set(None);
    YRX_RESULT::SUCCESS
}

/// Callback function passed to the scanner via [`yrx_scanner_on_matching_rule`]
/// which receives notifications about matching rules.
///
/// The callback receives a pointer to the matching rule, represented by a
/// [`YRX_RULE`] structure. This pointer is guaranteed to be valid while the
/// callback function is being executed, but it may be freed after the callback
/// function returns, so you cannot use the pointer outside the callback.
///
/// It also receives the `user_data` pointer that was passed to the  
/// [`yrx_scanner_on_matching_rule`] function, which can point to arbitrary
/// data owned by the user.
pub type YRX_ON_MATCHING_RULE = extern "C" fn(
    rule: *const YRX_RULE,
    user_data: *mut std::ffi::c_void,
) -> ();

/// Sets a callback function that is called by the scanner for each rule that
/// matched during a scan.
///
/// The `user_data` pointer can be used to provide additional context to your
/// callback function. If the callback is not set, the scanner doesn't notify
/// about matching rules.
///
/// See [`YRX_ON_MATCHING_RULE`] for more details.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_on_matching_rule(
    scanner: *mut YRX_SCANNER,
    callback: YRX_ON_MATCHING_RULE,
    user_data: *mut std::ffi::c_void,
) -> YRX_RESULT {
    if let Some(scanner) = scanner.as_mut() {
        scanner.on_matching_rule = Some((callback, user_data));
        YRX_RESULT::SUCCESS
    } else {
        YRX_RESULT::INVALID_ARGUMENT
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
/// be scanned, and you prefer to reuse this data instead of generating it again.
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
/// the module.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_set_module_output(
    scanner: *mut YRX_SCANNER,
    name: *const c_char,
    data: *const u8,
    len: usize,
) -> YRX_RESULT {
    if scanner.is_null() {
        return YRX_RESULT::INVALID_ARGUMENT;
    }

    let module_name = match CStr::from_ptr(name).to_str() {
        Ok(name) => name,
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
            return YRX_RESULT::INVALID_UTF8;
        }
    };

    let data = match slice_from_ptr_and_len(data, len) {
        Some(data) => data,
        None => return YRX_RESULT::INVALID_ARGUMENT,
    };

    let scanner = scanner.as_mut().unwrap();

    match scanner.inner.set_module_output_raw(module_name, data) {
        Ok(_) => {
            LAST_ERROR.set(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
            YRX_RESULT::SCAN_ERROR
        }
    }
}

unsafe extern "C" fn yrx_scanner_set_global<
    T: TryInto<yara_x::Variable, Error = yara_x::VariableError>,
>(
    scanner: *mut YRX_SCANNER,
    ident: *const c_char,
    value: T,
) -> YRX_RESULT {
    if scanner.is_null() {
        return YRX_RESULT::INVALID_ARGUMENT;
    }

    let ident = match CStr::from_ptr(ident).to_str() {
        Ok(ident) => ident,
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
            return YRX_RESULT::INVALID_UTF8;
        }
    };

    let scanner = scanner.as_mut().unwrap();

    match scanner.inner.set_global(ident, value) {
        Ok(_) => {
            LAST_ERROR.set(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
            YRX_RESULT::SCAN_ERROR
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
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
            YRX_RESULT::INVALID_UTF8
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
