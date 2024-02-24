use crate::compiler::{
    yrx_compiler_add_source, yrx_compiler_build, yrx_compiler_create,
    yrx_compiler_define_global_bool, yrx_compiler_define_global_float,
    yrx_compiler_define_global_int, yrx_compiler_define_global_str,
    yrx_compiler_destroy, yrx_compiler_new_namespace,
};
use crate::{
    yrx_buffer_destroy, yrx_rules_deserialize, yrx_rules_serialize,
    yrx_scanner_create, yrx_scanner_destroy, yrx_scanner_on_matching_rule,
    yrx_scanner_scan, YRX_BUFFER, YRX_RULE,
};
use std::ffi::{c_void, CString};

extern "C" fn callback(_rule: *const YRX_RULE, user_data: *mut c_void) {
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
                condition: \
                    some_bool and \
                    some_str == \"some_str\" and \
                    some_int == 1 and \
                    some_float == 1.5 \
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

        let mut rules = yrx_compiler_build(compiler);

        yrx_compiler_destroy(compiler);

        let mut buf: *mut YRX_BUFFER = std::ptr::null_mut();

        yrx_rules_serialize(rules, &mut buf);
        yrx_rules_deserialize((*buf).data, (*buf).length, &mut rules);
        yrx_buffer_destroy(buf);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);

        let mut matches = 0;

        yrx_scanner_on_matching_rule(
            scanner,
            callback,
            &mut matches as *mut i32 as *mut c_void,
        );

        yrx_scanner_scan(scanner, std::ptr::null(), 0);
        yrx_scanner_destroy(scanner);

        assert_eq!(matches, 1);
    }
}
