use std::ffi::{c_char, CStr};
use std::mem;

use yara_x::errors::{CompileError, VariableError};

use crate::{_yrx_set_last_error, YRX_RESULT, YRX_RULES};

/// A compiler that takes YARA source code and produces compiled rules.
pub struct YRX_COMPILER<'a> {
    inner: yara_x::Compiler<'a>,
    flags: u32,
}

/// Flag passed to [`yrx_compiler_create`] for producing colorful error
/// messages.
pub const YRX_COLORIZE_ERRORS: u32 = 1;

/// Flag passed to [`yrx_compiler_create`] that enables a more relaxed
/// syntax check for regular expressions.
///
/// YARA-X enforces stricter regular expression syntax compared to YARA.
/// For instance, YARA accepts invalid escape sequences and treats them
/// as literal characters (e.g., \R is interpreted as a literal 'R'). It
/// also allows some special characters to appear unescaped, inferring
/// their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
/// literal, but in `/foo{0,1}bar/` they form the repetition operator
/// `{0,1}`).
///
/// When this flag is set, YARA-X mimics YARA's behavior, allowing
/// constructs that YARA-X doesn't accept by default.
pub const YRX_RELAXED_RE_SYNTAX: u32 = 2;

/// Flag passed to [`yrx_compiler_create`] for treating slow patterns as
/// errors instead of warnings.
pub const YRX_ERROR_ON_SLOW_PATTERN: u32 = 4;

fn _yrx_compiler_create<'a>(flags: u32) -> yara_x::Compiler<'a> {
    let mut compiler = yara_x::Compiler::new();
    if flags & YRX_RELAXED_RE_SYNTAX != 0 {
        compiler.relaxed_re_syntax(true);
    }
    if flags & YRX_COLORIZE_ERRORS != 0 {
        compiler.colorize_errors(true);
    }
    if flags & YRX_ERROR_ON_SLOW_PATTERN != 0 {
        compiler.error_on_slow_pattern(true);
    }
    compiler
}

/// Creates a [`YRX_COMPILER`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_create(
    flags: u32,
    compiler: &mut *mut YRX_COMPILER,
) -> YRX_RESULT {
    *compiler = Box::into_raw(Box::new(YRX_COMPILER {
        inner: _yrx_compiler_create(flags),
        flags,
    }));

    YRX_RESULT::SUCCESS
}

/// Destroys a [`YRX_COMPILER`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_destroy(compiler: *mut YRX_COMPILER) {
    drop(Box::from_raw(compiler))
}

/// Adds a YARA source code to be compiled.
///
/// This function can be called multiple times.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_add_source(
    compiler: *mut YRX_COMPILER,
    src: *const c_char,
) -> YRX_RESULT {
    let compiler = if let Some(compiler) = compiler.as_mut() {
        compiler
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    let src = CStr::from_ptr(src);

    match compiler.inner.add_source(src.to_bytes()) {
        Ok(_) => {
            _yrx_set_last_error::<CompileError>(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::SYNTAX_ERROR
        }
    }
}

/// Tell the compiler that a YARA module is not supported.
///
/// Import statements for ignored modules will be ignored without errors but a
/// warning will be issued. Any rule that make use of an ignored module will be
/// ignored, while the rest of rules that don't rely on that module will be
/// correctly compiled.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_ignore_module(
    compiler: *mut YRX_COMPILER,
    module: *const c_char,
) -> YRX_RESULT {
    let compiler = if let Some(compiler) = compiler.as_mut() {
        compiler
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    let module = if let Ok(module) = CStr::from_ptr(module).to_str() {
        module
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    compiler.inner.ignore_module(module);

    YRX_RESULT::SUCCESS
}

/// Creates a new namespace.
///
/// Further calls to `yrx_compiler_add_source` will put the rules under the
/// newly created namespace.
///
/// The `namespace` argument must be pointer to null-terminated UTF-8 string.
/// If the string is not valid UTF-8 the result is an `INVALID_ARGUMENT` error.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_new_namespace(
    compiler: *mut YRX_COMPILER,
    namespace: *const c_char,
) -> YRX_RESULT {
    let compiler = if let Some(compiler) = compiler.as_mut() {
        compiler
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    let namespace = if let Ok(namespace) = CStr::from_ptr(namespace).to_str() {
        namespace
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    compiler.inner.new_namespace(namespace);

    YRX_RESULT::SUCCESS
}

/// Defines a global variable and sets its initial value.
///
/// Global variables must be defined before using `yrx_compiler_add_source`
/// for adding any YARA source code that uses those variables. The variable
/// will retain its initial value when the compiled rules are used for
/// scanning data, however each scanner can change the variable’s initial
/// value by calling `yrx_scanner_set_global`.
unsafe fn yrx_compiler_define_global<
    T: TryInto<yara_x::Variable, Error = yara_x::errors::VariableError>,
>(
    compiler: *mut YRX_COMPILER,
    ident: *const c_char,
    value: T,
) -> YRX_RESULT {
    let compiler = if let Some(compiler) = compiler.as_mut() {
        compiler
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    let ident = if let Ok(ident) = CStr::from_ptr(ident).to_str() {
        ident
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    match compiler.inner.define_global(ident, value) {
        Ok(_) => {
            _yrx_set_last_error::<VariableError>(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::VARIABLE_ERROR
        }
    }
}

/// Defines a global variable of string type and sets its initial value.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_define_global_str(
    compiler: *mut YRX_COMPILER,
    ident: *const c_char,
    value: *const c_char,
) -> YRX_RESULT {
    let value = if let Ok(value) = CStr::from_ptr(value).to_str() {
        value
    } else {
        return YRX_RESULT::INVALID_ARGUMENT;
    };

    yrx_compiler_define_global(compiler, ident, value)
}

/// Defines a global variable of bool type and sets its initial value.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_define_global_bool(
    compiler: *mut YRX_COMPILER,
    ident: *const c_char,
    value: bool,
) -> YRX_RESULT {
    yrx_compiler_define_global(compiler, ident, value)
}

/// Defines a global variable of integer type and sets its initial value.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_define_global_int(
    compiler: *mut YRX_COMPILER,
    ident: *const c_char,
    value: i64,
) -> YRX_RESULT {
    yrx_compiler_define_global(compiler, ident, value)
}

/// Defines a global variable of float type and sets its initial value.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_define_global_float(
    compiler: *mut YRX_COMPILER,
    ident: *const c_char,
    value: f64,
) -> YRX_RESULT {
    yrx_compiler_define_global(compiler, ident, value)
}

/// Builds the source code previously added to the compiler.
///
/// After calling this function the compiler is reset to its initial state,
/// (i.e: the state it had after returning from yrx_compiler_create) you can
/// keep using it by adding more sources and calling this function again.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_build(
    compiler: *mut YRX_COMPILER,
) -> *mut YRX_RULES {
    let compiler = if let Some(compiler) = compiler.as_mut() {
        compiler
    } else {
        return std::ptr::null_mut();
    };

    // As the build() method consumes the compiler, we need to take ownership
    // of it, but that implies that the inner compiler in the YRX_COMPILER
    // object must be replaced with something else, either a null value or a
    // new compiler.It is replaced with a new compiler, so that users of the
    // C API can keep using the YRX_COMPILER object after calling
    // yrx_compiler_build.
    let compiler = mem::replace(
        &mut compiler.inner,
        _yrx_compiler_create(compiler.flags),
    );

    Box::into_raw(Box::new(YRX_RULES(compiler.build())))
}
