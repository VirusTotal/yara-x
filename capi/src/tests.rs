use crate::compiler::{
    yrx_compiler_add_source, yrx_compiler_build, yrx_compiler_create,
};
use crate::{
    yrx_scanner_create, yrx_scanner_on_matching_rule, yrx_scanner_scan,
    YRX_RULE,
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

        let src =
            CString::new(b"rule test {condition: true}".to_vec()).unwrap();

        yrx_compiler_add_source(compiler, src.as_ptr());

        let rules = yrx_compiler_build(compiler);

        let mut scanner = std::ptr::null_mut();
        yrx_scanner_create(rules, &mut scanner);

        let mut matches = 0;

        yrx_scanner_on_matching_rule(
            scanner,
            callback,
            &mut matches as *mut i32 as *mut c_void,
        );

        yrx_scanner_scan(scanner, std::ptr::null(), 0);

        assert_eq!(matches, 1);
    }
}
