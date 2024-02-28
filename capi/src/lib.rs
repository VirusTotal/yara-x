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

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::mem::ManuallyDrop;
use std::ptr::slice_from_raw_parts_mut;
use std::slice;

mod compiler;
mod scanner;

#[cfg(test)]
mod tests;

pub use scanner::*;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

#[repr(C)]
pub enum YRX_RESULT {
    SUCCESS,
    PANIC,
    SYNTAX_ERROR,
    VARIABLE_ERROR,
    SCAN_ERROR,
    SCAN_TIMEOUT,
    INVALID_IDENTIFIER,
    INVALID_ARGUMENT,
    INVALID_UTF8,
    SERIALIZATION_ERROR,
}

/// A set of compiled YARA rules.
pub struct YRX_RULES(yara_x::Rules);

/// A single YARA rule.
pub struct YRX_RULE<'a, 'r>(yara_x::Rule<'a, 'r>);

/// A set of patterns declared in a YARA rule.
#[repr(C)]
pub struct YRX_PATTERNS {
    /// Number of patterns.
    num_patterns: usize,
    /// Pointer to an array of YRX_PATTERN structures. The array has
    /// num_patterns items. If num_patterns is zero this pointer is invalid
    /// and should not be de-referenced.
    patterns: *mut YRX_PATTERN,
}

impl Drop for YRX_PATTERNS {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(slice_from_raw_parts_mut(
                self.patterns,
                self.num_patterns,
            )));
        }
    }
}

/// A pattern within a rule.
#[repr(C)]
pub struct YRX_PATTERN {
    /// Pattern's identifier (i.e: $a, $foo)
    identifier: *mut c_char,
    /// Number of matches found for this pattern.
    num_matches: usize,
    /// Pointer to an array of YRX_MATCH structures describing the matches
    /// for this pattern. The array has num_matches items. If num_matches is
    /// zero this pointer is invalid and should not be de-referenced.
    matches: *mut YRX_MATCH,
}

impl Drop for YRX_PATTERN {
    fn drop(&mut self) {
        unsafe {
            drop(CString::from_raw(self.identifier));
            drop(Box::from_raw(slice_from_raw_parts_mut(
                self.matches,
                self.num_matches,
            )));
        }
    }
}

/// Contains information about a pattern match.
#[repr(C)]
pub struct YRX_MATCH {
    pub offset: usize,
    pub length: usize,
}

/// Represents a buffer with arbitrary data.
#[repr(C)]
pub struct YRX_BUFFER {
    /// Pointer to the data contained in the buffer.
    pub data: *mut u8,
    /// Length of data in bytes.
    pub length: usize,
}

impl Drop for YRX_BUFFER {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(slice_from_raw_parts_mut(
                self.data,
                self.length,
            )));
        }
    }
}

/// Compiles YARA source code and creates a [`YRX_RULES`] object that contains
/// the compiled rules.
///
/// The rules must be destroyed with [`yrx_rules_destroy`].
#[no_mangle]
pub unsafe extern "C" fn yrx_compile(
    src: *const c_char,
    rules: &mut *mut YRX_RULES,
) -> YRX_RESULT {
    let c_str = CStr::from_ptr(src);
    match yara_x::compile(c_str.to_bytes()) {
        Ok(r) => {
            *rules = Box::into_raw(Box::new(YRX_RULES(r)));
            LAST_ERROR.set(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
            YRX_RESULT::SYNTAX_ERROR
        }
    }
}

/// Serializes the rules as a sequence of bytes.
///
/// In the address indicated by the `buf` pointer, the function will copy a
/// `YRX_BUFFER*` pointer. The `YRX_BUFFER` structure represents a buffer
/// that contains the serialized rules. This structure has a pointer to the
/// data itself, and its length.
///
/// This [`YRX_BUFFER`] must be destroyed with [`yrx_buffer_destroy`].
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_serialize(
    rules: *mut YRX_RULES,
    buf: &mut *mut YRX_BUFFER,
) -> YRX_RESULT {
    if let Some(rules) = rules.as_ref() {
        match rules.0.serialize() {
            Ok(serialized) => {
                let serialized = serialized.into_boxed_slice();
                let mut serialized = ManuallyDrop::new(serialized);
                *buf = Box::into_raw(Box::new(YRX_BUFFER {
                    data: serialized.as_mut_ptr(),
                    length: serialized.len(),
                }));
                LAST_ERROR.set(None);
                YRX_RESULT::SUCCESS
            }
            Err(err) => {
                LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
                YRX_RESULT::SERIALIZATION_ERROR
            }
        }
    } else {
        YRX_RESULT::INVALID_ARGUMENT
    }
}

/// Deserializes the rules from a sequence of bytes produced by
/// [`yrx_rules_serialize`].
///
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_deserialize(
    data: *const u8,
    len: usize,
    rules: &mut *mut YRX_RULES,
) -> YRX_RESULT {
    match yara_x::Rules::deserialize(slice::from_raw_parts(data, len)) {
        Ok(r) => {
            *rules = Box::into_raw(Box::new(YRX_RULES(r)));
            LAST_ERROR.set(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
            YRX_RESULT::SERIALIZATION_ERROR
        }
    }
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
) -> YRX_RESULT {
    if let Some(rule) = rule.as_ref() {
        *ident = rule.0.identifier().as_ptr();
        *len = rule.0.identifier().len();
        LAST_ERROR.set(None);
        YRX_RESULT::SUCCESS
    } else {
        YRX_RESULT::INVALID_ARGUMENT
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
) -> YRX_RESULT {
    if let Some(rule) = rule.as_ref() {
        *ns = rule.0.namespace().as_ptr();
        *len = rule.0.namespace().len();
        LAST_ERROR.set(None);
        YRX_RESULT::SUCCESS
    } else {
        YRX_RESULT::INVALID_ARGUMENT
    }
}

/// Returns all the patterns defined by a rule.
///
/// Each pattern contains information about whether it matched or not, and where
/// in the data it matched. The patterns are represented by a [`YRX_PATTERNS`]
/// object that must be destroyed with [`yrx_patterns_destroy`] when not needed
/// anymore.
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_patterns(
    rule: *const YRX_RULE,
) -> *mut YRX_PATTERNS {
    let patterns_iter = rule.as_ref().unwrap().0.patterns();
    let mut patterns = Vec::with_capacity(patterns_iter.len());

    for pattern in patterns_iter {
        let matches = pattern
            .matches()
            .map(|m| YRX_MATCH {
                offset: m.range().start,
                length: m.range().len(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        // Prevent `matches` from being dropped at the end of the current
        // scope. We are taking a pointer to `matches` and storing it in a
        // YRX_PATTERN structure. The `YRX_PATTERN::drop` method takes care
        // of dropping the slice of matches.
        let mut matches = ManuallyDrop::new(matches);

        patterns.push(YRX_PATTERN {
            identifier: CString::new(pattern.identifier()).unwrap().into_raw(),
            num_matches: matches.len(),
            matches: matches.as_mut_ptr(),
        });
    }

    let mut patterns = ManuallyDrop::new(patterns);

    Box::into_raw(Box::new(YRX_PATTERNS {
        num_patterns: patterns.len(),
        patterns: patterns.as_mut_ptr(),
    }))
}

/// Destroys a [`YRX_PATTERNS`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_patterns_destroy(patterns: *mut YRX_PATTERNS) {
    drop(Box::from_raw(patterns));
}

/// Destroys a [`YRX_BUFFER`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_buffer_destroy(buf: *mut YRX_BUFFER) {
    drop(Box::from_raw(buf));
}

/// Returns the error message for the most recent function in this API
/// invoked by the current thread.
///
/// The returned pointer is only valid until this thread calls some other
/// function, as it can modify the last error and render the pointer to
/// a previous error message invalid. Also, the pointer will be null if
/// the most recent function was successfully.
#[no_mangle]
pub unsafe extern "C" fn yrx_last_error() -> *const c_char {
    LAST_ERROR.with_borrow(|last_error| {
        if let Some(last_error) = last_error {
            last_error.as_ptr()
        } else {
            std::ptr::null()
        }
    })
}
