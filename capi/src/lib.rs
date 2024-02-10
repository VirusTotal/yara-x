/*! C bindings for the YARA-X library.

This crate defines the C-compatible API that C/C++ programs can use for
interfacing with the YARA-X Rust library. When this crate is built, the header
file `capi/include/yara-x.h` is generated automatically using [`cbindgen`][1],
together with dynamic-linking and static-linking versions of a `libyara-x-capi`
that can be found in the `target` directory.

This crate is not intended to be used by other Rust programs.

[1]: https://github.com/mozilla/cbindgen
*/

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr};

mod scanner;

pub use scanner::*;

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
        Err(_) => return YRX_ERROR::SYNTAX_ERROR,
    };

    YRX_ERROR::SUCCESS
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
