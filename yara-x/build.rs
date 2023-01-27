use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{env, fs};

use protobuf_codegen::Codegen;
use protobuf_parse::Parser;
use yara_x_proto::exts::module_options as yara_module_options;

fn main() {
    println!("cargo:rerun-if-changed=src/modules");
    println!("cargo:rerun-if-changed=src/modules/protos");

    let out_dir = env::var_os("OUT_DIR").unwrap();

    let mut proto_compiler = Codegen::new();
    let mut proto_parser = Parser::new();

    proto_compiler
        .pure()
        .cargo_out_dir("protos")
        //.out_dir("src/modules/protos")
        .include("../yara-x-proto/src")
        .include("src/modules/protos")
        .input("../yara-x-proto/src/yara.proto");

    proto_parser.include("../yara-x-proto/src").include("src/modules/protos");

    for entry in fs::read_dir("src/modules/protos").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if let Some(extension) = path.extension() {
            if extension == "proto" {
                proto_compiler.input(&path);
                proto_parser.input(&path);
            }
        }
    }

    // Generate .rs files for .proto files in src/modules/protos
    proto_compiler.run_from_script();

    // Look for .proto files that describe a YARA module. A proto that
    // describes a YARA module has yara.module_options, like...
    //
    // option (yara.module_options) = {
    //   name : "test"
    //   root_message: "Test"
    //   rust_module: "test"
    // };
    //
    let mut modules = Vec::new();
    for proto_file in proto_parser.file_descriptor_set().unwrap().file {
        if let Some(module_options) =
            yara_module_options.get(&proto_file.options)
        {
            modules.push((
                module_options.name.unwrap(),
                proto_file
                    .name
                    .unwrap()
                    .strip_suffix(".proto")
                    .unwrap()
                    .to_string(),
                module_options.rust_module,
                module_options.root_message.unwrap(),
            ));
        }
    }

    // Create the modules.rs files, with an entry for each YARA module
    // that has an associated Rust module. Each entry in the file looks
    // like:
    //
    //  #[cfg(feature = "foo_module")]
    //  pub mod foo;
    //
    let mut modules_rs = File::create("src/modules/modules.rs").unwrap();

    // Create the add_modules.rs files, with an entry for each proto that
    // defines a YARA module. Each entry looks like:
    //
    //  #[cfg(feature = "foo_module")]
    //  add_module!(modules, "foo", foo, Some(foo::__main__ as MainFn));
    //
    let mut add_modules_rs =
        File::create(Path::new(&out_dir).join("add_modules.rs")).unwrap();

    write!(
        modules_rs,
        "// File generated automatically by build.rs. Do not edit."
    )
    .unwrap();

    write!(add_modules_rs, "{{").unwrap();

    for m in modules {
        let name = m.0;
        let proto_mod = m.1;
        let rust_mod = m.2;
        let root_message = m.3;

        if let Some(rust_mod) = &rust_mod {
            write!(
                modules_rs,
                r#"
#[cfg(feature = "{name}-module")]
pub mod {rust_mod};"#,
            )
            .unwrap();
        }

        // If the YARA module has an associated Rust module, this module must
        // have a function named "main". If the YARA module doesn't have an
        // associated YARA module, the main function is set to None.
        let main_fn = if let Some(rust_mod) = &rust_mod {
            format!("Some({}::__main__ as MainFn)", rust_mod)
        } else {
            "None".to_string()
        };

        let rust_mod_name = if let Some(rust_mod) = &rust_mod {
            format!(r#"Some("{}")"#, rust_mod)
        } else {
            "None".to_string()
        };

        write!(
            add_modules_rs,
            r#"
#[cfg(feature = "{name}-module")]
add_module!(modules, "{name}", {proto_mod}, {root_message}, {rust_mod_name}, {main_fn});
            "#,
        )
        .unwrap();
    }

    write!(add_modules_rs, "}}").unwrap();
}
