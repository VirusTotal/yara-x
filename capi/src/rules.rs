use std::ffi::{c_char, c_int, c_void, CString};
use std::mem::ManuallyDrop;
use std::slice;

use yara_x::errors::SerializationError;

use crate::{_yrx_set_last_error, YRX_BUFFER, YRX_RESULT, YRX_RULE};

/// A set of compiled YARA rules.
pub struct YRX_RULES(yara_x::Rules);

impl YRX_RULES {
    /// Creates a new YRX_RULES in [`Box`].
    pub fn boxed(rules: yara_x::Rules) -> Box<Self> {
        Box::new(Self(rules))
    }

    /// Returns a reference to the [`yara_x::Rules`] wrapped by this
    /// type.
    #[inline]
    pub fn inner(&self) -> &yara_x::Rules {
        &self.0
    }
}

/// Callback function passed to [`yrx_scanner_on_matching_rule`] or
/// [`yrx_rules_iter`].
///
/// The callback receives a pointer to a rule, represented by a [`YRX_RULE`]
/// structure. This pointer is guaranteed to be valid while the callback
/// function is being executed, but it may be freed after the callback function
/// returns, so you cannot use the pointer outside the callback.
///
/// It also receives the `user_data` pointer that can point to arbitrary data
/// owned by the user.
pub type YRX_RULE_CALLBACK =
    extern "C" fn(rule: *const YRX_RULE, user_data: *mut c_void) -> ();

/// Iterates over the compiled rules, calling the callback function for each
/// rule.
///
/// The `user_data` pointer can be used to provide additional context to your
/// callback function.
///
/// See [`YRX_RULE_CALLBACK`] for more details.
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_iter(
    rules: *const YRX_RULES,
    callback: YRX_RULE_CALLBACK,
    user_data: *mut c_void,
) -> YRX_RESULT {
    if let Some(rules) = rules.as_ref() {
        for r in rules.inner().iter() {
            let rule = YRX_RULE::new(r);
            callback(&rule as *const YRX_RULE, user_data);
        }
        YRX_RESULT::SUCCESS
    } else {
        YRX_RESULT::INVALID_ARGUMENT
    }
}

/// Returns the total number of rules.
///
/// Returns -1 in case of error.
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_count(rules: *mut YRX_RULES) -> c_int {
    if let Some(rules) = rules.as_ref() {
        rules.inner().iter().len() as c_int
    } else {
        -1
    }
}

/// Serializes the rules as a sequence of bytes.
///
/// In the address indicated by the `buf` pointer, the function will copy a
/// `YRX_BUFFER*` pointer. The `YRX_BUFFER` structure represents a buffer
/// that contains the serialized rules. This structure has a pointer to the
/// data itself, and its length.
///
/// The [`YRX_BUFFER`] must be destroyed with [`yrx_buffer_destroy`].
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_serialize(
    rules: *const YRX_RULES,
    buf: &mut *mut YRX_BUFFER,
) -> YRX_RESULT {
    if let Some(rules) = rules.as_ref() {
        match rules.inner().serialize() {
            Ok(serialized) => {
                let serialized = serialized.into_boxed_slice();
                let mut serialized = ManuallyDrop::new(serialized);
                *buf = Box::into_raw(Box::new(YRX_BUFFER {
                    data: serialized.as_mut_ptr(),
                    length: serialized.len(),
                }));
                _yrx_set_last_error::<SerializationError>(None);
                YRX_RESULT::SUCCESS
            }
            Err(err) => {
                _yrx_set_last_error(Some(err));
                YRX_RESULT::SERIALIZATION_ERROR
            }
        }
    } else {
        YRX_RESULT::INVALID_ARGUMENT
    }
}

/// Deserializes the rules from a sequence of bytes produced by
/// [`yrx_rules_serialize`].
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_deserialize(
    data: *const u8,
    len: usize,
    rules: &mut *mut YRX_RULES,
) -> YRX_RESULT {
    match yara_x::Rules::deserialize(slice::from_raw_parts(data, len)) {
        Ok(r) => {
            *rules = Box::into_raw(YRX_RULES::boxed(r));
            _yrx_set_last_error::<SerializationError>(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::SERIALIZATION_ERROR
        }
    }
}

/// Callback function passed to [`yrx_rules_iter_imports`].
///
/// The callback is called for every module imported by the rules, and it
/// receives a pointer to the module's name. This pointer is guaranteed to be
/// valid while the callback function is being executed, but it will be freed
/// after the callback function returns, so you cannot use the pointer outside
/// the callback.
///
/// The callback also receives a `user_data` pointer that can point to arbitrary
/// data owned by the user.
pub type YRX_IMPORT_CALLBACK =
    extern "C" fn(module_name: *const c_char, user_data: *mut c_void) -> ();

/// Iterates over the modules imported by the rules, calling the callback with
/// the name of each imported module.
///
/// The `user_data` pointer can be used to provide additional context to your
/// callback function.
///
/// See [`YRX_IMPORT_CALLBACK`] for more details.
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_iter_imports(
    rules: *const YRX_RULES,
    callback: YRX_IMPORT_CALLBACK,
    user_data: *mut c_void,
) -> YRX_RESULT {
    if let Some(rules) = rules.as_ref() {
        for import in rules.inner().imports() {
            let import = CString::new(import).unwrap();
            callback(import.as_ptr(), user_data);
        }
        YRX_RESULT::SUCCESS
    } else {
        YRX_RESULT::INVALID_ARGUMENT
    }
}

/// Destroys a [`YRX_RULES`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_rules_destroy(rules: *mut YRX_RULES) {
    drop(Box::from_raw(rules))
}
