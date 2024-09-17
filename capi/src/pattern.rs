use std::ffi::c_void;

use crate::{_yrx_set_last_error, YRX_MATCH, YRX_RESULT};

/// A pattern defined in a rule.
pub struct YRX_PATTERN<'a, 'r>(yara_x::Pattern<'a, 'r>);

impl<'a, 'r> YRX_PATTERN<'a, 'r> {
    /// Creates a new YRX_PATTERN.
    pub fn new(pattern: yara_x::Pattern<'a, 'r>) -> Self {
        Self(pattern)
    }
}

/// Returns the name of the pattern represented by [`YRX_PATTERN`].
///
/// Arguments `ident` and `len` are output parameters that receive pointers
/// to a `const uint8_t*` and `size_t`, where this function will leave a pointer
/// to the rule's name and its length, respectively. The rule's name is *NOT*
/// null-terminated, and the pointer will be valid as long as the [`YRX_RULES`]
/// object that contains the pattern is not freed. The name is guaranteed to be
/// a valid UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn yrx_pattern_identifier(
    pattern: *const YRX_PATTERN,
    ident: &mut *const u8,
    len: &mut usize,
) -> YRX_RESULT {
    if let Some(pattern) = pattern.as_ref() {
        *ident = pattern.0.identifier().as_ptr();
        *len = pattern.0.identifier().len();
        _yrx_set_last_error::<String>(None);
        YRX_RESULT::SUCCESS
    } else {
        YRX_RESULT::INVALID_ARGUMENT
    }
}

/// Callback function passed to [`yrx_pattern_iter_matches`].
///
/// The callback is called by all matches found for a pattern, and it receives
/// a pointer to a [`YRX_MATCH`] structure. This pointer is guaranteed to be
/// valid while the callback function is being executed, but it will be freed
/// after the callback function returns, so you cannot use the pointer, or any
/// other pointer contained in the structure, outside the callback.
///
/// The callback also receives a `user_data` pointer that can point to arbitrary
/// data owned by the user.
pub type YRX_MATCH_CALLBACK =
    extern "C" fn(match_: *const YRX_MATCH, user_data: *mut c_void) -> ();

/// Iterates over the matches of a pattern, calling the callback with a pointer
/// to a [`YRX_MATCH`] structure for each pattern.
///
/// The `user_data` pointer can be used to provide additional context to your
/// callback function.
///
/// See [`YRX_MATCH_CALLBACK`] for more details.
#[no_mangle]
pub unsafe extern "C" fn yrx_pattern_iter_matches(
    pattern: *const YRX_PATTERN,
    callback: YRX_MATCH_CALLBACK,
    user_data: *mut c_void,
) -> YRX_RESULT {
    let matches_iter = if let Some(pattern) = pattern.as_ref() {
        pattern.0.matches()
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    for m in matches_iter {
        callback(
            &YRX_MATCH { offset: m.range().start, length: m.range().len() },
            user_data,
        )
    }

    YRX_RESULT::SUCCESS
}
