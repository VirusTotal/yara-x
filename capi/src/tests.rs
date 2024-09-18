use crate::compiler::{
    yrx_compiler_add_source, yrx_compiler_add_source_with_origin,
    yrx_compiler_build, yrx_compiler_create, yrx_compiler_define_global_bool,
    yrx_compiler_define_global_float, yrx_compiler_define_global_int,
    yrx_compiler_define_global_str, yrx_compiler_destroy,
    yrx_compiler_new_namespace,
};
use crate::{
    yrx_buffer_destroy, yrx_last_error, yrx_rule_identifier,
    yrx_rule_iter_metadata, yrx_rule_iter_patterns, yrx_rule_namespace,
    yrx_rules_deserialize, yrx_rules_destroy, yrx_rules_iter,
    yrx_rules_iter_imports, yrx_rules_serialize, yrx_scanner_create,
    yrx_scanner_destroy, yrx_scanner_on_matching_rule, yrx_scanner_scan,
    yrx_scanner_set_global_bool, yrx_scanner_set_global_float,
    yrx_scanner_set_global_int, yrx_scanner_set_global_str,
    yrx_scanner_set_timeout, YRX_BUFFER, YRX_METADATA, YRX_PATTERN,
    YRX_RESULT, YRX_RULE,
};

use std::ffi::{c_char, c_void, CStr, CString};

extern "C" fn on_rule_iter(_rule: *const YRX_RULE, user_data: *mut c_void) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
}

extern "C" fn on_import_iter(_module: *const c_char, user_data: *mut c_void) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
}

extern "C" fn on_metadata_iter(
    _metadata: *const YRX_METADATA,
    user_data: *mut c_void,
) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
}

extern "C" fn on_pattern_iter(
    _pattern: *const YRX_PATTERN,
    user_data: *mut c_void,
) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
}

extern "C" fn on_rule_match(rule: *const YRX_RULE, user_data: *mut c_void) {
    let mut ptr = std::ptr::null();
    let mut len = 0;

    unsafe {
        yrx_rule_namespace(rule, &mut ptr, &mut len);
        yrx_rule_identifier(rule, &mut ptr, &mut len);

        let mut count = 0;
        yrx_rule_iter_metadata(
            rule,
            on_metadata_iter,
            &mut count as *mut i32 as *mut c_void,
        );
        // The rule has three metadata entries.
        assert_eq!(count, 3);

        let mut count = 0;
        yrx_rule_iter_patterns(
            rule,
            on_pattern_iter,
            &mut count as *mut i32 as *mut c_void,
        );
        // The rule has one pattern.
        assert_eq!(count, 1);
    }

    let ptr = user_data as *mut i32;
    let matches = unsafe { ptr.as_mut().unwrap() };
    *matches += 1;
}

#[test]
fn capi() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        // TODO: Use c-string literals cr#"rule test ..."# when we MSRV
        // is bumped to 1.77.
        // https://doc.rust-lang.org/edition-guide/rust-2021/c-string-literals.html
        let src = CString::new(
            br#"
            import "pe"
            rule test {
                meta:
                    some_int = 1
                    some_string = "foo"
                    some_bytes = "\x01\x00\x02"
                strings:
                    $foo = "foo"
                condition:
                    $foo or (
                    some_bool and
                    some_str == "some_str" and
                    some_int == 1 and
                    some_float == 1.5)
            }"#,
        )
        .unwrap();

        let some_bool = CString::new(b"some_bool").unwrap();
        let some_str = CString::new(b"some_str").unwrap();
        let some_int = CString::new(b"some_int").unwrap();
        let some_float = CString::new(b"some_float").unwrap();

        yrx_compiler_define_global_int(compiler, some_int.as_ptr(), 1);
        yrx_compiler_define_global_float(compiler, some_float.as_ptr(), 1.5);
        yrx_compiler_define_global_bool(compiler, some_bool.as_ptr(), true);
        yrx_compiler_define_global_str(
            compiler,
            some_str.as_ptr(),
            some_str.as_ptr(),
        );

        let namespace = CString::new(b"foo").unwrap();
        yrx_compiler_new_namespace(compiler, namespace.as_ptr());
        yrx_compiler_add_source(compiler, src.as_ptr());

        assert_eq!(yrx_last_error(), std::ptr::null());

        let mut rules = yrx_compiler_build(compiler);

        yrx_compiler_destroy(compiler);

        let mut num_rules = 0;
        yrx_rules_iter(
            rules,
            on_rule_iter,
            &mut num_rules as *mut i32 as *mut c_void,
        );
        assert_eq!(num_rules, 1);

        let mut num_imports = 0;
        yrx_rules_iter_imports(
            rules,
            on_import_iter,
            &mut num_imports as *mut i32 as *mut c_void,
        );
        assert_eq!(num_imports, 1);

        let mut buf: *mut YRX_BUFFER = std::ptr::null_mut();

        yrx_rules_serialize(rules, &mut buf);
        yrx_rules_deserialize((*buf).data, (*buf).length, &mut rules);
        yrx_buffer_destroy(buf);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);

        let mut matches = 0;

        yrx_scanner_set_timeout(scanner, 60);
        yrx_scanner_on_matching_rule(
            scanner,
            on_rule_match,
            &mut matches as *mut i32 as *mut c_void,
        );

        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 1);

        matches = 0;

        // After changing the value of `some_bool` to false, the rule doesn't
        // match anymore.
        yrx_scanner_set_global_bool(scanner, some_bool.as_ptr(), false);
        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 0);

        // Set all variables to the expected values, and the rule should match
        // again.
        yrx_scanner_set_global_bool(scanner, some_bool.as_ptr(), true);
        yrx_scanner_set_global_int(scanner, some_int.as_ptr(), 1);
        yrx_scanner_set_global_float(scanner, some_float.as_ptr(), 1.5);
        yrx_scanner_set_global_str(
            scanner,
            some_str.as_ptr(),
            some_str.as_ptr(),
        );

        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 1);

        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

#[test]
fn capi_errors() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = CString::new(b"rule test { condition: foo }").unwrap();
        let origin = CString::new("test.yar").unwrap();

        assert_eq!(
            yrx_compiler_add_source_with_origin(
                compiler,
                src.as_ptr(),
                origin.as_ptr()
            ),
            YRX_RESULT::SYNTAX_ERROR
        );

        assert_eq!(
            CStr::from_ptr(yrx_last_error()),
            CStr::from_bytes_with_nul(
                b"error[E009]: unknown identifier `foo`
 --> test.yar:1:24
  |
1 | rule test { condition: foo }
  |                        ^^^ this identifier has not been declared
  |\0"
            )
            .unwrap()
        );

        yrx_compiler_destroy(compiler);
    }
}
