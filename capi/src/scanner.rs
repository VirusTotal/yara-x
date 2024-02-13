use std::ffi::{c_char, CString};
use std::slice;
use std::time::Duration;
use yara_x::ScanError;

use crate::{YRX_RESULT, YRX_RULE, YRX_RULES};

/// A scanner that scans data with a set of compiled YARA rules.
pub struct YRX_SCANNER<'s> {
    inner: yara_x::Scanner<'s>,
    on_matching_rule: Option<(YRX_ON_MATCHING_RULE, *mut std::ffi::c_void)>,
    last_error: Option<CString>,
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
        last_error: None,
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

    // `data` is allowed to be null as long as `len` is 0. This case is handled
    // as an empty slice.
    if data.is_null() && len > 0 {
        return YRX_RESULT::INVALID_ARGUMENT;
    }

    let data = if data.is_null() || len == 0 {
        &[]
    } else {
        slice::from_raw_parts(data, len)
    };

    let scanner = scanner.as_mut().unwrap();
    let scan_results = scanner.inner.scan(data);

    if let Err(err) = scan_results {
        scanner.last_error = Some(CString::new(err.to_string()).unwrap());
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

/// Returns the error message for the most recent error returned by the
/// scanner.
///
/// The returned pointer is only valid until the next call to any of the
/// yrx_scanner_xxxx functions. A call any of these functions can modify
/// the last error, rendering the pointer to a previous error message
/// invalid. Also, the pointer will be null if the scanner hasn't returned
/// any error.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_last_error(
    scanner: *const YRX_SCANNER,
) -> *const c_char {
    let scanner = if let Some(scanner) = scanner.as_ref() {
        scanner
    } else {
        return std::ptr::null();
    };

    if let Some(last_error) = scanner.last_error.as_ref() {
        last_error.as_ptr()
    } else {
        std::ptr::null()
    }
}
