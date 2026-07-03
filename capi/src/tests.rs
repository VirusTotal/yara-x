use crate::compiler::{
    yrx_compiler_add_include_dir, yrx_compiler_add_source,
    yrx_compiler_add_source_with_origin, yrx_compiler_ban_module,
    yrx_compiler_build, yrx_compiler_create, yrx_compiler_define_global_bool,
    yrx_compiler_define_global_float, yrx_compiler_define_global_int,
    yrx_compiler_define_global_json, yrx_compiler_define_global_str,
    yrx_compiler_destroy, yrx_compiler_enable_feature,
    yrx_compiler_errors_json, yrx_compiler_ignore_module,
    yrx_compiler_max_warnings, yrx_compiler_new_namespace,
    yrx_compiler_warnings_json,
};
use crate::{
    YRX_BUFFER, YRX_MATCH, YRX_METADATA, YRX_METADATA_TYPE, YRX_PATTERN,
    YRX_RESULT, YRX_RULE, yrx_buffer_destroy, yrx_compile, yrx_last_error,
    yrx_pattern_identifier, yrx_pattern_iter_matches, yrx_rule_identifier,
    yrx_rule_iter_metadata, yrx_rule_iter_patterns, yrx_rule_iter_tags,
    yrx_rule_namespace, yrx_rules_count, yrx_rules_deserialize,
    yrx_rules_destroy, yrx_rules_iter, yrx_rules_iter_imports,
    yrx_rules_serialize, yrx_scanner_clear_profiling_data, yrx_scanner_create,
    yrx_scanner_destroy, yrx_scanner_fast_scan, yrx_scanner_finish,
    yrx_scanner_iter_slowest_rules, yrx_scanner_on_console_log,
    yrx_scanner_on_matching_rule, yrx_scanner_scan, yrx_scanner_scan_block,
    yrx_scanner_scan_file, yrx_scanner_set_global_bool,
    yrx_scanner_set_global_float, yrx_scanner_set_global_int,
    yrx_scanner_set_global_json, yrx_scanner_set_global_str,
    yrx_scanner_set_module_data, yrx_scanner_set_module_output,
    yrx_scanner_set_timeout,
};

use std::ffi::{CStr, c_char, c_void};

use assert_call::{CallRecorder, call};

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
    metadata: *const YRX_METADATA,
    user_data: *mut c_void,
) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
    unsafe {
        if let Some(m) = metadata.as_ref() {
            assert!(!m.identifier.is_null());
            match m.value_type {
                YRX_METADATA_TYPE::YRX_I64 => {
                    let _ = m.value.r#i64;
                }
                YRX_METADATA_TYPE::YRX_F64 => {
                    let _ = m.value.r#f64;
                }
                YRX_METADATA_TYPE::YRX_BOOLEAN => {
                    let _ = m.value.boolean;
                }
                YRX_METADATA_TYPE::YRX_STRING => {
                    assert!(!m.value.string.is_null());
                }
                YRX_METADATA_TYPE::YRX_BYTES => {
                    assert!(
                        m.value.bytes.length > 0
                            && !m.value.bytes.data.is_null()
                    );
                }
            }
        }
    }
}

extern "C" fn on_pattern_match_iter(
    match_: *const YRX_MATCH,
    user_data: *mut c_void,
) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
    unsafe {
        assert!((*match_).length > 0);
    }
}

extern "C" fn on_slowest_rule_iter(
    _namespace: *const c_char,
    _rule: *const c_char,
    _pattern_matching_time: f64,
    _condition_exec_time: f64,
    user_data: *mut c_void,
) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
}

extern "C" fn on_pattern_iter(
    pattern: *const YRX_PATTERN,
    user_data: *mut c_void,
) {
    let ptr = user_data as *mut i32;
    let count = unsafe { ptr.as_mut().unwrap() };
    *count += 1;
    unsafe {
        let mut ident_ptr = std::ptr::null();
        let mut ident_len = 0;
        assert_eq!(
            yrx_pattern_identifier(pattern, &mut ident_ptr, &mut ident_len),
            YRX_RESULT::YRX_SUCCESS
        );
        assert!(!ident_ptr.is_null() && ident_len > 0);

        let mut match_count = 0;
        assert_eq!(
            yrx_pattern_iter_matches(
                pattern,
                on_pattern_match_iter,
                &mut match_count as *mut i32 as *mut c_void,
            ),
            YRX_RESULT::YRX_SUCCESS
        );
    }
}

extern "C" fn on_tag_iter(_tag: *const c_char, user_data: *mut c_void) {
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
        // The rule has five metadata entries.
        assert_eq!(count, 5);

        let mut count = 0;
        yrx_rule_iter_patterns(
            rule,
            on_pattern_iter,
            &mut count as *mut i32 as *mut c_void,
        );
        // The rule has one pattern.
        assert_eq!(count, 1);

        let mut count = 0;
        yrx_rule_iter_tags(
            rule,
            on_tag_iter,
            &mut count as *mut i32 as *mut c_void,
        );
        // The rule has two tags.
        assert_eq!(count, 2);
    }

    let ptr = user_data as *mut i32;
    let matches = unsafe { ptr.as_mut().unwrap() };
    *matches += 1;
}

extern "C" fn on_rule_match_increase_counter(
    _rule: *const YRX_RULE,
    user_data: *mut c_void,
) {
    let ptr = user_data as *mut i32;
    let matches = unsafe { ptr.as_mut().unwrap() };
    *matches += 1;
}

extern "C" fn on_console_log(message: *const c_char) {
    let cstr = unsafe { CStr::from_ptr(message) };
    call!("{}", cstr.to_string_lossy());
}

#[test]
fn capi_console_log() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = cr#"
        import "console"

        rule test {
            condition:
                console.log("AXSERS")
        }
        "#;

        yrx_compiler_add_source(compiler, src.as_ptr());
        let rules = yrx_compiler_build(compiler);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);
        yrx_scanner_on_console_log(scanner, on_console_log);
        let mut recorder = CallRecorder::new_local();
        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        recorder.verify("AXSERS");

        yrx_rules_destroy(rules);
        yrx_scanner_destroy(scanner);
        yrx_compiler_destroy(compiler);
    }
}
#[test]
fn capi() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = cr#"
            import "pe"
            rule test : tag1 tag2 {
                meta:
                    some_int = 1
                    some_float = 1.5
                    some_bool = true
                    some_string = "foo"
                    some_bytes = "\x01\x00\x02"
                strings:
                    $foo = "foo"
                condition:
                    $foo or (
                    some_bool and
                    some_str == "some_str" and
                    some_int == 1 and
                    some_float == 1.5 and 
                    some_map.str == "foo" and
                    some_map.array[0] == 1 and
                    some_map.map.str == "bar" )
            }"#;

        let some_bool = c"some_bool";
        let some_str = c"some_str";
        let some_int = c"some_int";
        let some_float = c"some_float";
        let some_map = c"some_map";
        let some_map_value = cr#"{
           "str": "foo",
           "array": [1, 2, 3],
           "map": { "str": "bar" }
        }"#;

        yrx_compiler_define_global_int(compiler, some_int.as_ptr(), 1);
        yrx_compiler_define_global_float(compiler, some_float.as_ptr(), 1.5);
        yrx_compiler_define_global_bool(compiler, some_bool.as_ptr(), true);

        yrx_compiler_define_global_str(
            compiler,
            some_str.as_ptr(),
            some_str.as_ptr(),
        );

        yrx_compiler_define_global_json(
            compiler,
            some_map.as_ptr(),
            some_map_value.as_ptr(),
        );

        let feature = c"foo";
        yrx_compiler_enable_feature(compiler, feature.as_ptr());

        let namespace = c"foo";
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
        assert_eq!(yrx_rules_count(rules), 1);

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

        yrx_scanner_set_global_json(
            scanner,
            some_map.as_ptr(),
            some_map_value.as_ptr(),
        );

        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 1);

        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

#[test]
fn capi_modules() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = cr#"
        import "cuckoo"

        rule test {
            condition:
                cuckoo.network.tcp(/192\.168\.1\.1/, 443)
        }
        "#;

        let module_name = c"cuckoo";
        let module_metadata = cr#"
        {
            "network": {
                "tcp": [{ "dport": 443, "dst": "192.168.1.1" }]
            },
            "behavior": {
                "summary": {}
            }
        }
        "#;

        let module_metadata2 = cr#"
        {
            "network": {
                "tcp": [{ "dport": 443, "dst": "192.168.1.2" }]
            },
            "behavior": {
                "summary": {}
            }
        }
        "#;

        yrx_compiler_add_source(compiler, src.as_ptr());
        let rules = yrx_compiler_build(compiler);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);

        let mut matches = 0;
        yrx_scanner_on_matching_rule(
            scanner,
            on_rule_match_increase_counter,
            &mut matches as *mut i32 as *mut c_void,
        );
        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 0);
        assert_eq!(yrx_last_error(), std::ptr::null());

        yrx_scanner_set_module_data(
            scanner,
            module_name.as_ptr(),
            module_metadata.as_ptr() as *const u8,
            module_metadata.to_bytes().len(),
        );
        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 1);
        assert_eq!(yrx_last_error(), std::ptr::null());

        // Module data are cleaned after scanning.
        matches = 0;
        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 0);
        assert_eq!(yrx_last_error(), std::ptr::null());

        // Scanning with two different module data, first is matched, second is not.
        yrx_scanner_set_module_data(
            scanner,
            module_name.as_ptr(),
            module_metadata.as_ptr() as *const u8,
            module_metadata.to_bytes().len(),
        );
        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 1);
        assert_eq!(yrx_last_error(), std::ptr::null());

        matches = 0;
        yrx_scanner_set_module_data(
            scanner,
            module_name.as_ptr(),
            module_metadata2.as_ptr() as *const u8,
            module_metadata2.to_bytes().len(),
        );
        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        assert_eq!(matches, 0);
        assert_eq!(yrx_last_error(), std::ptr::null());

        yrx_rules_destroy(rules);
        yrx_scanner_destroy(scanner);
        yrx_compiler_destroy(compiler);
    }
}

#[test]
fn capi_blocks() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = cr#"
rule test1 { strings: $a = "foo" condition: $a }
rule test2 { strings: $a = "bar" condition: $a }
"#;
        yrx_compiler_add_source(compiler, src.as_ptr());

        let rules = yrx_compiler_build(compiler);
        yrx_compiler_destroy(compiler);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);

        let mut matches = 0;
        yrx_scanner_on_matching_rule(
            scanner,
            on_rule_match_increase_counter,
            &mut matches as *mut i32 as *mut c_void,
        );

        let block1 = b"foo";
        let block2 = b"bar";

        yrx_scanner_scan_block(scanner, 0, block1.as_ptr(), block1.len());
        yrx_scanner_scan_block(scanner, 10, block2.as_ptr(), block2.len());

        yrx_scanner_finish(scanner);

        assert_eq!(matches, 2);

        // Scan again, the scanner should be reset.
        matches = 0;
        let block3 = b"foobar";
        yrx_scanner_scan_block(scanner, 0, block3.as_ptr(), block3.len());
        yrx_scanner_finish(scanner);
        assert_eq!(matches, 2);

        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

#[test]
fn capi_errors() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = c"rule test { condition: foo }";
        let origin = c"test.yar";

        assert_eq!(
            yrx_compiler_add_source_with_origin(
                compiler,
                src.as_ptr(),
                origin.as_ptr()
            ),
            YRX_RESULT::YRX_SYNTAX_ERROR
        );

        assert_eq!(
            CStr::from_ptr(yrx_last_error()),
            c"error[E009]: unknown identifier `foo`
 --> test.yar:1:24
  |
1 | rule test { condition: foo }
  |                        ^^^ this identifier has not been declared"
        );

        yrx_compiler_destroy(compiler);
    }
}

#[test]
fn capi_fast_scan() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = c"rule test { strings: $a = \"foo\" condition: $a }";
        yrx_compiler_add_source(compiler, src.as_ptr());

        let rules = yrx_compiler_build(compiler);
        yrx_compiler_destroy(compiler);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);

        // Enable fast scan mode
        yrx_scanner_fast_scan(scanner, true);

        let mut matches = 0;
        yrx_scanner_on_matching_rule(
            scanner,
            on_rule_match_increase_counter,
            &mut matches as *mut i32 as *mut c_void,
        );

        let data = b"foofoofoo";
        yrx_scanner_scan(scanner, data.as_ptr(), data.len());

        assert_eq!(matches, 1);

        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

#[test]
fn capi_null_args() {
    unsafe {
        assert_eq!(
            yrx_compiler_add_source(std::ptr::null_mut(), std::ptr::null()),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_add_source_with_origin(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_add_include_dir(
                std::ptr::null_mut(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_ignore_module(std::ptr::null_mut(), std::ptr::null()),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_ban_module(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_max_warnings(std::ptr::null_mut(), 10),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_enable_feature(
                std::ptr::null_mut(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_new_namespace(std::ptr::null_mut(), std::ptr::null()),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_define_global_str(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_define_global_bool(
                std::ptr::null_mut(),
                std::ptr::null(),
                true
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_define_global_int(
                std::ptr::null_mut(),
                std::ptr::null(),
                0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_define_global_float(
                std::ptr::null_mut(),
                std::ptr::null(),
                0.0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_define_global_json(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert!(yrx_compiler_build(std::ptr::null_mut()).is_null());
        assert_eq!(
            yrx_compiler_errors_json(
                std::ptr::null_mut(),
                &mut std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_compiler_warnings_json(
                std::ptr::null_mut(),
                &mut std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        yrx_compiler_destroy(std::ptr::null_mut());

        assert_eq!(yrx_rules_count(std::ptr::null_mut()), -1);
        let mut buf = std::ptr::null_mut();
        assert_eq!(
            yrx_rules_serialize(std::ptr::null(), &mut buf),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_rules_iter(
                std::ptr::null(),
                on_rule_iter,
                std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_rules_iter_imports(
                std::ptr::null(),
                on_import_iter,
                std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        yrx_rules_destroy(std::ptr::null_mut());

        assert_eq!(
            yrx_rule_identifier(
                std::ptr::null(),
                &mut std::ptr::null(),
                &mut 0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_rule_namespace(
                std::ptr::null(),
                &mut std::ptr::null(),
                &mut 0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_rule_iter_metadata(
                std::ptr::null(),
                on_metadata_iter,
                std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_rule_iter_patterns(
                std::ptr::null(),
                on_pattern_iter,
                std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_rule_iter_tags(
                std::ptr::null(),
                on_tag_iter,
                std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );

        assert_eq!(
            yrx_pattern_identifier(
                std::ptr::null(),
                &mut std::ptr::null(),
                &mut 0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_pattern_iter_matches(
                std::ptr::null(),
                on_pattern_match_iter,
                std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );

        assert_eq!(
            yrx_scanner_create(
                std::ptr::null_mut(),
                &mut std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_timeout(std::ptr::null_mut(), 10),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_fast_scan(std::ptr::null_mut(), true),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_scan(std::ptr::null_mut(), std::ptr::null(), 0),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_scan_file(std::ptr::null_mut(), c"test".as_ptr()),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_scan_block(
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_finish(std::ptr::null_mut()),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_on_matching_rule(
                std::ptr::null_mut(),
                on_rule_match_increase_counter,
                std::ptr::null_mut()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_module_output(
                std::ptr::null_mut(),
                c"pe".as_ptr(),
                std::ptr::null(),
                0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_module_data(
                std::ptr::null_mut(),
                c"pe".as_ptr(),
                std::ptr::null(),
                0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_global_str(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_global_bool(
                std::ptr::null_mut(),
                std::ptr::null(),
                true
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_global_int(
                std::ptr::null_mut(),
                std::ptr::null(),
                1
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_global_float(
                std::ptr::null_mut(),
                std::ptr::null(),
                1.0
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        assert_eq!(
            yrx_scanner_set_global_json(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null()
            ),
            YRX_RESULT::YRX_INVALID_ARGUMENT
        );
        yrx_scanner_on_console_log(std::ptr::null_mut(), on_console_log);
        let res = yrx_scanner_iter_slowest_rules(
            std::ptr::null_mut(),
            5,
            on_slowest_rule_iter,
            std::ptr::null_mut(),
        );
        assert!(
            res == YRX_RESULT::YRX_INVALID_ARGUMENT
                || res == YRX_RESULT::YRX_NOT_SUPPORTED
        );
        let res = yrx_scanner_clear_profiling_data(std::ptr::null_mut());
        assert!(
            res == YRX_RESULT::YRX_INVALID_ARGUMENT
                || res == YRX_RESULT::YRX_NOT_SUPPORTED
        );
        yrx_scanner_destroy(std::ptr::null_mut());
    }
}

#[test]
fn capi_compiler_extra() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        assert_eq!(
            yrx_compiler_add_include_dir(compiler, c"/tmp".as_ptr()),
            YRX_RESULT::YRX_SUCCESS
        );
        assert_eq!(
            yrx_compiler_ignore_module(compiler, c"pe".as_ptr()),
            YRX_RESULT::YRX_SUCCESS
        );
        assert_eq!(
            yrx_compiler_ban_module(
                compiler,
                c"elf".as_ptr(),
                c"banned".as_ptr(),
                c"elf is banned".as_ptr()
            ),
            YRX_RESULT::YRX_SUCCESS
        );
        assert_eq!(
            yrx_compiler_max_warnings(compiler, 5),
            YRX_RESULT::YRX_SUCCESS
        );

        let src = c"rule test { condition: true }";
        yrx_compiler_add_source(compiler, src.as_ptr());

        let mut err_buf = std::ptr::null_mut();
        assert_eq!(
            yrx_compiler_errors_json(compiler, &mut err_buf),
            YRX_RESULT::YRX_SUCCESS
        );
        assert!(!err_buf.is_null());
        yrx_buffer_destroy(err_buf);

        let mut warn_buf = std::ptr::null_mut();
        assert_eq!(
            yrx_compiler_warnings_json(compiler, &mut warn_buf),
            YRX_RESULT::YRX_SUCCESS
        );
        assert!(!warn_buf.is_null());
        yrx_buffer_destroy(warn_buf);

        let rules = yrx_compiler_build(compiler);
        yrx_compiler_destroy(compiler);
        yrx_rules_destroy(rules);
    }
}

#[test]
fn capi_scanner_extra() {
    unsafe {
        let mut compiler = std::ptr::null_mut();
        yrx_compiler_create(0, &mut compiler);

        let src = c"rule test { condition: true }";
        yrx_compiler_add_source(compiler, src.as_ptr());
        let rules = yrx_compiler_build(compiler);
        yrx_compiler_destroy(compiler);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);

        // Scan file (use Cargo.toml in manifest dir or current dir)
        let res = yrx_scanner_scan_file(scanner, c"Cargo.toml".as_ptr());
        assert!(
            res == YRX_RESULT::YRX_SUCCESS
                || res == YRX_RESULT::YRX_SCAN_ERROR
        );

        // Test set_module_output with invalid bytes
        assert_eq!(
            yrx_scanner_set_module_output(
                scanner,
                c"pe".as_ptr(),
                b"invalid".as_ptr(),
                7
            ),
            YRX_RESULT::YRX_SCAN_ERROR
        );

        let mut count = 0;
        let res = yrx_scanner_iter_slowest_rules(
            scanner,
            10,
            on_slowest_rule_iter,
            &mut count as *mut i32 as *mut c_void,
        );
        assert!(
            res == YRX_RESULT::YRX_SUCCESS
                || res == YRX_RESULT::YRX_NOT_SUPPORTED
        );

        yrx_scanner_clear_profiling_data(scanner);

        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

#[test]
fn capi_serialization_and_compile() {
    unsafe {
        let mut rules = std::ptr::null_mut();
        assert_eq!(
            yrx_compile(c"rule test { condition: true }".as_ptr(), &mut rules),
            YRX_RESULT::YRX_SUCCESS
        );
        assert!(!rules.is_null());

        let mut bad_rules = std::ptr::null_mut();
        assert_eq!(
            yrx_compile(
                c"rule bad { condition: foo }".as_ptr(),
                &mut bad_rules
            ),
            YRX_RESULT::YRX_SYNTAX_ERROR
        );

        // Test deserialize with invalid data
        let invalid_bytes = b"not valid yara rules";
        let mut des_rules = std::ptr::null_mut();
        assert_eq!(
            yrx_rules_deserialize(
                invalid_bytes.as_ptr(),
                invalid_bytes.len(),
                &mut des_rules
            ),
            YRX_RESULT::YRX_SERIALIZATION_ERROR
        );

        yrx_rules_destroy(rules);
    }
}
