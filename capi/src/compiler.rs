use crate::{LAST_ERROR, YRX_RESULT, YRX_RULES};
use std::ffi::{c_char, CStr, CString};
use std::mem;

/// A compiler that takes YARA source code and produces compiled rules.
pub struct YRX_COMPILER<'a> {
    inner: yara_x::Compiler<'a>,
}

/// Creates a [`YRX_COMPILER`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_compiler_create(
    compiler: &mut *mut YRX_COMPILER,
) -> YRX_RESULT {
    *compiler = Box::into_raw(Box::new(YRX_COMPILER {
        inner: yara_x::Compiler::new(),
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
            LAST_ERROR.set(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
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
    T: TryInto<yara_x::Variable, Error = yara_x::VariableError>,
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
            LAST_ERROR.set(None);
            YRX_RESULT::SUCCESS
        }
        Err(err) => {
            LAST_ERROR.set(Some(CString::new(err.to_string()).unwrap()));
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
/// you can keep using it by adding more sources and calling this function
/// again.
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
    let compiler = mem::replace(&mut compiler.inner, yara_x::Compiler::new());

    Box::into_raw(Box::new(YRX_RULES(compiler.build())))
}
