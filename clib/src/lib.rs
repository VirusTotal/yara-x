#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr};
use std::slice;

#[repr(C)]
pub enum YRX_ERROR {
    SUCCESS,
    PANIC,
    SYNTAX_ERROR,
    INVALID_ARGUMENT,
}

/// A set of compiled YARA rules.
pub struct YRX_RULES(yara_x::Rules);

/// A single YARA rule.
pub struct YRX_RULE<'a, 'r>(yara_x::Rule<'a, 'r>);

/// A pattern within a rule.
pub struct YRX_PATTERN {
    identifier: String,
    matches: Vec<YRX_MATCH>,
}

/// Contains information about a pattern match.
#[repr(C)]
pub struct YRX_MATCH {
    pub offset: usize,
    pub length: usize,
}

/// The set of patterns declared in a YARA rule.
pub struct YRX_PATTERNS(Vec<YRX_PATTERN>);

/// A scanner that scans data with a set of compiled YARA rules.
pub struct YRX_SCANNER<'s> {
    inner: yara_x::Scanner<'s>,
    on_matching_rule: Option<(YRX_ON_MATCHING_RULE, *mut std::ffi::c_void)>,
}

/// Compiles YARA source code and creates a [`YRX_RULES`] object that contains
/// the compiled rules.
///
/// The rules must be destroyed with [`yrx_rules_destroy`].
#[no_mangle]
pub unsafe extern "C" fn yrx_compile(
    src: *const c_char,
    rules: &mut *mut YRX_RULES,
) -> YRX_ERROR {
    let c_str = CStr::from_ptr(src);

    match yara_x::compile(c_str.to_bytes()) {
        Ok(r) => *rules = Box::into_raw(Box::new(YRX_RULES(r))),
        Err(err) => return YRX_ERROR::SYNTAX_ERROR,
    };

    YRX_ERROR::SUCCESS
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

    if let Err(_) = scan_results {
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

/// Destroys a [`YRX_RULES`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_destroy(rules: *mut YRX_RULES) {
    drop(Box::from_raw(rules))
}

/// Returns the name of the rule represented by [`YRX_RULE`].
///
/// Arguments `ident` and `len` are output parameters that receive pointers
/// to a `const uint8_t*` and `size_t`, where this function will leave a pointer
/// to the rule's name and its length, respectively. The rule's name is *NOT*
/// null-terminated, and the pointer will be valid as long as the [`YRX_RULES`]
/// object that contains the rule is not freed. The name is guaranteed to be a
/// valid UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_identifier(
    rule: *const YRX_RULE,
    ident: &mut *const u8,
    len: &mut usize,
) -> YRX_ERROR {
    if let Some(rule) = rule.as_ref() {
        *ident = rule.0.identifier().as_ptr();
        *len = rule.0.identifier().len();
        YRX_ERROR::SUCCESS
    } else {
        YRX_ERROR::INVALID_ARGUMENT
    }
}

/// Returns the namespace of the rule represented by [`YRX_RULE`].
///
/// Arguments `ns` and `len` are output parameters that receive pointers to a
/// `const uint8_t*` and `size_t`, where this function will leave a pointer
/// to the rule's namespace and its length, respectively. The namespace is *NOT*
/// null-terminated, and the pointer will be valid as long as the [`YRX_RULES`]
/// object that contains the rule is not freed. The namespace is guaranteed to
/// be a valid UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_namespace(
    rule: *const YRX_RULE,
    ns: &mut *const u8,
    len: &mut usize,
) -> YRX_ERROR {
    if let Some(rule) = rule.as_ref() {
        *ns = rule.0.namespace().as_ptr();
        *len = rule.0.namespace().len();
        YRX_ERROR::SUCCESS
    } else {
        YRX_ERROR::INVALID_ARGUMENT
    }
}

/// Returns the all patterns defined by a rule, each pattern contains
/// information about whether it matched or not, and where in the data it
/// matched.
///
/// The [`YRX_PATTERNS`] object must be destroyed with [`yrx_patterns_destroy`].
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_patterns(
    rule: *const YRX_RULE,
) -> *const YRX_PATTERNS {
    if let Some(rule) = rule.as_ref() {
        return Box::into_raw(Box::new(YRX_PATTERNS(
            rule.0
                .patterns()
                .map(|pat| YRX_PATTERN {
                    identifier: pat.identifier().to_string(),
                    matches: pat
                        .matches()
                        .map(|m| YRX_MATCH {
                            offset: m.range().start,
                            length: m.range().len(),
                        })
                        .collect(),
                })
                .collect(),
        )));
    } else {
        std::ptr::null()
    }
}

/// Returns the number of patterns in a given [`YRX_PATTERNS`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_patterns_count(
    patterns: *const YRX_PATTERNS,
) -> i32 {
    if let Some(patterns) = patterns.as_ref() {
        patterns.0.len() as i32
    } else {
        -1
    }
}

/// Returns the pattern with the give `index`, from a set of patterns represented
/// by a [`YRX_PATTERNS`] object.
///
/// The index must be between 0 and the value returned by [`yrx_patterns_count`],
/// otherwise the result will be a null pointer. The result is also a null
/// pointer if `patterns` is null.
#[no_mangle]
pub unsafe extern "C" fn yrx_patterns_get(
    patterns: *mut YRX_PATTERNS,
    index: usize,
) -> *const YRX_PATTERN {
    if let Some(pattern) =
        patterns.as_ref().and_then(|patterns| patterns.0.get(index))
    {
        pattern
    } else {
        std::ptr::null()
    }
}

/// Destroys a [`YRX_PATTERNS`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_patterns_destroy(patterns: *mut YRX_PATTERNS) {
    drop(Box::from_raw(patterns))
}

/// Returns the identifier of rule's pattern represented by [`YRX_PATTERN`].
///
/// Arguments `ident` and `len` are output parameters that receive pointers to a
/// `const uint8_t*` and `size_t`, where this function will leave a pointer
/// to the rule's name and its length, respectively. The identifier is *NOT*
/// null-terminated, and the pointer will be valid as long as the [`YRX_RULES`]
/// object that contains the rule is not freed. The name is guaranteed to be a
/// valid UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn yrx_pattern_identifier(
    pattern: *const YRX_PATTERN,
    ident: &mut *const u8,
    len: &mut usize,
) -> YRX_ERROR {
    if let Some(pattern) = pattern.as_ref() {
        *ident = pattern.identifier.as_ptr();
        *len = pattern.identifier.len();
        YRX_ERROR::SUCCESS
    } else {
        YRX_ERROR::INVALID_ARGUMENT
    }
}

#[no_mangle]
pub unsafe extern "C" fn yrx_pattern_matches(
    pattern: *const YRX_PATTERN,
    matches: &mut *const YRX_MATCH,
    len: &mut usize,
) -> YRX_ERROR {
    if let Some(pattern) = pattern.as_ref() {
        *matches = pattern.matches.as_ptr();
        *len = pattern.matches.len();
        YRX_ERROR::SUCCESS
    } else {
        YRX_ERROR::INVALID_ARGUMENT
    }
}
