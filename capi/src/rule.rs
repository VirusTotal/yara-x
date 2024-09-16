use std::ffi::{c_void, CString};
use std::mem::ManuallyDrop;

use crate::{
    _yrx_set_last_error, YRX_METADATA, YRX_METADATA_BYTES, YRX_METADATA_ENTRY,
    YRX_METADATA_VALUE, YRX_METADATA_VALUE_TYPE, YRX_PATTERN, YRX_RESULT,
};

/// A single YARA rule.
pub struct YRX_RULE<'a, 'r>(yara_x::Rule<'a, 'r>);

impl<'a, 'r> YRX_RULE<'a, 'r> {
    /// Creates a new YRX_RULE.
    pub fn new(rule: yara_x::Rule<'a, 'r>) -> Self {
        Self(rule)
    }
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
        _yrx_set_last_error::<String>(None);
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
        _yrx_set_last_error::<String>(None);
        YRX_RESULT::SUCCESS
    } else {
        YRX_RESULT::INVALID_ARGUMENT
    }
}

/// Returns the metadata associated to a rule.
///
/// The metadata is represented by a [`YRX_METADATA`] object that must be
/// destroyed with [`yrx_metadata_destroy`] when not needed anymore.
///
/// This function returns a null pointer when `rule` is null or the
/// rule doesn't have any metadata.
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_metadata(
    rule: *const YRX_RULE,
) -> *mut YRX_METADATA {
    let metadata = if let Some(rule) = rule.as_ref() {
        rule.0.metadata()
    } else {
        return std::ptr::null_mut();
    };

    if metadata.is_empty() {
        return std::ptr::null_mut();
    }

    let mut entries = Vec::with_capacity(metadata.len());

    for (identifier, value) in metadata {
        let identifier = CString::new(identifier).unwrap().into_raw();

        match value {
            yara_x::MetaValue::Integer(v) => {
                entries.push(YRX_METADATA_ENTRY {
                    identifier,
                    value_type: YRX_METADATA_VALUE_TYPE::I64,
                    value: YRX_METADATA_VALUE { r#i64: v },
                });
            }
            yara_x::MetaValue::Float(v) => {
                entries.push(YRX_METADATA_ENTRY {
                    identifier,
                    value_type: YRX_METADATA_VALUE_TYPE::F64,
                    value: YRX_METADATA_VALUE { r#f64: v },
                });
            }
            yara_x::MetaValue::Bool(v) => {
                entries.push(YRX_METADATA_ENTRY {
                    identifier,
                    value_type: YRX_METADATA_VALUE_TYPE::BOOLEAN,
                    value: YRX_METADATA_VALUE { boolean: v },
                });
            }
            yara_x::MetaValue::String(v) => {
                entries.push(YRX_METADATA_ENTRY {
                    identifier,
                    value_type: YRX_METADATA_VALUE_TYPE::STRING,
                    value: YRX_METADATA_VALUE {
                        string: CString::new(v).unwrap().into_raw(),
                    },
                });
            }
            yara_x::MetaValue::Bytes(v) => {
                let v = v.to_vec().into_boxed_slice();
                let mut v = ManuallyDrop::new(v);
                entries.push(YRX_METADATA_ENTRY {
                    identifier,
                    value_type: YRX_METADATA_VALUE_TYPE::BYTES,
                    value: YRX_METADATA_VALUE {
                        bytes: YRX_METADATA_BYTES {
                            data: v.as_mut_ptr(),
                            length: v.len(),
                        },
                    },
                });
            }
        };
    }

    let mut entries = ManuallyDrop::new(entries);

    Box::into_raw(Box::new(YRX_METADATA {
        num_entries: entries.len(),
        entries: entries.as_mut_ptr(),
    }))
}

/// Callback function passed to [`yrx_rule_iter_patterns`].
///
/// The callback receives a pointer to a pattern. This pointer is guaranteed
/// to be valid while the callback function is being executed, but it may be
/// freed after the callback function returns, so you cannot use the pointer
/// outside the callback.
///
/// It also receives the `user_data` pointer that can point to arbitrary data
/// owned by the user.
pub type YRX_PATTERN_CALLBACK =
    extern "C" fn(pattern: *const YRX_PATTERN, user_data: *mut c_void) -> ();

/// Iterates over the patterns in a rule, calling the callback with a pointer
/// to a [`YRX_PATTERN`] structure for each pattern.
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_iter_patterns(
    rule: *mut YRX_RULE,
    callback: YRX_PATTERN_CALLBACK,
    user_data: *mut c_void,
) -> YRX_RESULT {
    let patterns_iter = if let Some(rule) = rule.as_ref() {
        rule.0.patterns()
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    for pattern in patterns_iter {
        callback(&YRX_PATTERN::new(pattern), user_data)
    }

    YRX_RESULT::SUCCESS
}
