use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_file = "include/yara_x.h".to_owned();

    match cbindgen::generate(crate_dir) {
        Ok(header) => {
            header.write_to_file(output_file);
        }
        Err(err) => {
            panic!("{}", err)
        }
    }
}
