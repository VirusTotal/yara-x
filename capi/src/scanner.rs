use std::slice;

use crate::{YRX_ERROR, YRX_RULE, YRX_RULES};

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
) -> YRX_ERROR {
    if let Some(rules) = rules.as_ref() {
        let s = yara_x::Scanner::new(&rules.0);
        *scanner = Box::into_raw(Box::new(YRX_SCANNER {
            inner: s,
            on_matching_rule: None,
        }));
        YRX_ERROR::SUCCESS
    } else {
        YRX_ERROR::INVALID_ARGUMENT
    }
}

/// Scans a data buffer.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_scan(
    scanner: *mut YRX_SCANNER,
    data: *const u8,
    len: usize,
) -> YRX_ERROR {
    if scanner.is_null() {
        return YRX_ERROR::INVALID_ARGUMENT;
    }

    // Data is allowed to be null as long as len is 0. This case is handled
    // as an empty slice.
    if data.is_null() && len > 0 {
        return YRX_ERROR::INVALID_ARGUMENT;
    }

    let scanner = scanner.as_mut().unwrap();
    let data = slice::from_raw_parts(data, len);
    let scan_results = scanner.inner.scan(data);

    if scan_results.is_err() {
        // TODO: return appropriate error
        return YRX_ERROR::PANIC;
    }

    let scan_results = scan_results.unwrap();

    if let Some((callback, user_data)) = scanner.on_matching_rule {
        for r in scan_results.matching_rules() {
            let rule = YRX_RULE(r);
            callback(&rule as *const YRX_RULE, user_data);
        }
    }

    YRX_ERROR::SUCCESS
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
type YRX_ON_MATCHING_RULE = extern "C" fn(
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
) -> YRX_ERROR {
    if let Some(scanner) = scanner.as_mut() {
        scanner.on_matching_rule = Some((callback, user_data));
        YRX_ERROR::SUCCESS
    } else {
        YRX_ERROR::INVALID_ARGUMENT
    }
}

/// Destroys a [`YRX_SCANNER`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_scanner_destroy(scanner: *mut YRX_SCANNER) {
    drop(Box::from_raw(scanner))
}
