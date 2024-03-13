use std::env;
use vcpkg;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_file = "include/yara-x.h".to_owned();

    vcpkg::find_package("libmagic").unwrap();
    vcpkg::find_package("bzip2").unwrap();
    vcpkg::find_package("zlib").unwrap();

    match cbindgen::generate(crate_dir) {
        Ok(header) => {
            header.write_to_file(output_file);
        }
        Err(err) => {
            panic!("{}", err)
        }
    }
}
