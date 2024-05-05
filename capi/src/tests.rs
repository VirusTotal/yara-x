use crate::compiler::{
    yrx_compiler_add_source, yrx_compiler_build, yrx_compiler_create,
    yrx_compiler_define_global_bool, yrx_compiler_define_global_float,
    yrx_compiler_define_global_int, yrx_compiler_define_global_str,
    yrx_compiler_destroy, yrx_compiler_new_namespace,
};
use crate::{
    yrx_buffer_destroy, yrx_last_error, yrx_patterns_destroy,
    yrx_rule_identifier, yrx_rule_namespace, yrx_rule_patterns,
    yrx_rules_deserialize, yrx_rules_destroy, yrx_rules_serialize,
    yrx_scanner_create, yrx_scanner_destroy, yrx_scanner_on_matching_rule,
    yrx_scanner_scan, yrx_scanner_set_global_bool,
    yrx_scanner_set_global_float, yrx_scanner_set_global_int,
    yrx_scanner_set_global_str, yrx_scanner_set_timeout, YRX_BUFFER, YRX_RULE,
};
use std::ffi::{c_void, CString};

extern "C" fn callback(rule: *const YRX_RULE, user_data: *mut c_void) {
    let mut ptr = std::ptr::null();
    let mut len = 0;

    unsafe {
        yrx_rule_namespace(rule, &mut ptr, &mut len);
        yrx_rule_identifier(rule, &mut ptr, &mut len);

        let patterns = yrx_rule_patterns(rule);
        assert_eq!((*patterns).num_patterns, 1);
        yrx_patterns_destroy(patterns);
    }

    let ptr = user_data as *mut i32;
    let matches = unsafe { ptr.as_mut().unwrap() };
    *matches += 1;
}

#[test]
fn capi() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(&mut compiler);

        let src = CString::new(
            b"rule test {\
                strings: \
                    $foo = \"foo\" \
                condition: \
                    $foo or ( \
                    some_bool and \
                    some_str == \"some_str\" and \
                    some_int == 1 and \
                    some_float == 1.5) \
            }"
            .to_vec(),
        )
        .unwrap();

        let some_bool = CString::new(b"some_bool".to_vec()).unwrap();
        let some_str = CString::new(b"some_str".to_vec()).unwrap();
        let some_int = CString::new(b"some_int".to_vec()).unwrap();
        let some_float = CString::new(b"some_float".to_vec()).unwrap();

        yrx_compiler_define_global_int(compiler, some_int.as_ptr(), 1);
        yrx_compiler_define_global_float(compiler, some_float.as_ptr(), 1.5);
        yrx_compiler_define_global_bool(compiler, some_bool.as_ptr(), true);
        yrx_compiler_define_global_str(
            compiler,
            some_str.as_ptr(),
            some_str.as_ptr(),
        );

        let namespace = CString::new(b"foo".to_vec()).unwrap();
        yrx_compiler_new_namespace(compiler, namespace.as_ptr());
        yrx_compiler_add_source(compiler, src.as_ptr());

        assert_eq!(yrx_last_error(), std::ptr::null());

        let mut rules = yrx_compiler_build(compiler);

        yrx_compiler_destroy(compiler);

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
            callback,
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
