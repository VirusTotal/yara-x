use std::ffi::{c_void, CString};
use yara_x::MetaValue;

use crate::{
    _yrx_set_last_error, YRX_METADATA, YRX_METADATA_BYTES, YRX_METADATA_TYPE,
    YRX_METADATA_VALUE, YRX_PATTERN, YRX_RESULT,
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

/// Callback function passed to [`yrx_rule_iter_metadata`].
///
/// The callback is called for each metadata in the rule, and receives a pointer
/// to a [`YRX_METADATA`] structure. This pointer is guaranteed to be valid
/// while the callback function is being executed, but it will be freed after
/// the callback function returns, so you cannot use the pointer, or any other
/// pointer contained in this structure, outside the callback.
///
/// The callback also receives a `user_data` pointer that can point to arbitrary
/// data owned by the user.
pub type YRX_METADATA_CALLBACK =
    extern "C" fn(metadata: *const YRX_METADATA, user_data: *mut c_void) -> ();

/// Iterates over the metadata of a rule, calling the callback with a pointer
/// to a [`YRX_METADATA`] structure for each metadata in the rule.
///
/// The `user_data` pointer can be used to provide additional context to your
/// callback function.
///
/// See [`YRX_METADATA_CALLBACK`] for more details.
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_iter_metadata(
    rule: *const YRX_RULE,
    callback: YRX_METADATA_CALLBACK,
    user_data: *mut c_void,
) -> YRX_RESULT {
    let metadata_iter = if let Some(rule) = rule.as_ref() {
        rule.0.metadata()
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    for (identifier, value) in metadata_iter {
        let identifier = CString::new(identifier).unwrap();
        let string;

        let (ty, val) = match value {
            MetaValue::Integer(v) => {
                (YRX_METADATA_TYPE::I64, YRX_METADATA_VALUE { r#i64: v })
            }
            MetaValue::Float(v) => {
                (YRX_METADATA_TYPE::F64, YRX_METADATA_VALUE { r#f64: v })
            }
            MetaValue::Bool(v) => {
                (YRX_METADATA_TYPE::BOOLEAN, YRX_METADATA_VALUE { boolean: v })
            }
            MetaValue::String(v) => {
                string = CString::new(v).unwrap();
                (
                    YRX_METADATA_TYPE::STRING,
                    YRX_METADATA_VALUE { string: string.as_ptr() },
                )
            }
            MetaValue::Bytes(v) => (
                YRX_METADATA_TYPE::BYTES,
                YRX_METADATA_VALUE {
                    bytes: YRX_METADATA_BYTES {
                        length: v.len(),
                        data: v.as_ptr(),
                    },
                },
            ),
        };

        callback(
            &YRX_METADATA {
                identifier: identifier.as_ptr(),
                value_type: ty,
                value: val,
            },
            user_data,
        )
    }

    YRX_RESULT::SUCCESS
}

/// Callback function passed to [`yrx_rule_iter_patterns`].
///
/// The callback is called for each pattern defined in the rule, and it receives
/// a pointer to a [`YRX_PATTERN`] structure. This pointer is guaranteed to be
/// valid while the callback function is being executed, but it will be freed
/// after the callback function returns, so you cannot use this pointer, or
/// any other pointer contained in the structure, outside the callback.
///
/// The callback also receives a `user_data` pointer that can point to arbitrary
/// data owned by the user.
pub type YRX_PATTERN_CALLBACK =
    extern "C" fn(pattern: *const YRX_PATTERN, user_data: *mut c_void) -> ();

/// Iterates over the patterns in a rule, calling the callback with a pointer
/// to a [`YRX_PATTERN`] structure for each pattern.
///
/// The `user_data` pointer can be used to provide additional context to your
/// callback function.
///
/// See [`YRX_PATTERN_CALLBACK`] for more details.
#[no_mangle]
pub unsafe extern "C" fn yrx_rule_iter_patterns(
    rule: *const YRX_RULE,
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
