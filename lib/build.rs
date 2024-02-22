use anyhow::Context;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::{env, fs};

use protobuf_codegen::Codegen;
use protobuf_parse::Parser;
use serde::{Deserialize, Serialize};

use yara_x_proto::exts::module_options as yara_module_options;

#[derive(Serialize, Deserialize)]
struct ProtocConfig {
    includes: Vec<String>,
    inputs: Vec<String>,
}

fn main() {
    println!("cargo:rerun-if-changed=src/modules");
    println!("cargo:rerun-if-changed=src/modules/protos");

    let out_dir = env::var_os("OUT_DIR").unwrap();

    let mut proto_compiler = Codegen::new();
    let mut proto_parser = Parser::new();

    proto_compiler
        .pure()
        .cargo_out_dir("protos")
        .include("../proto/src")
        .include("../proto-yaml/src")
        .include("src/modules/protos")
        .input("../proto/src/yara.proto")
        .input("../proto-yaml/src/yaml.proto");

    proto_parser
        .include("../proto/src")
        .include("../proto-yaml/src")
        .include("src/modules/protos");

    // All `.proto` files in src/modules/protos must be compiled
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

    if let Ok(proto_files) = env::var("YRX_EXTRA_PROTOS") {
        for path in proto_files.split(' ').collect::<Vec<_>>() {
            let path = if let Some(base_path) =
                env::var("YRX_EXTRA_PROTOS_BASE_PATH").ok()
            {
                PathBuf::from(base_path).join(path)
            } else {
                PathBuf::from(path)
            };

            let path = fs::canonicalize(&path)
                .with_context(|| format!("`{:?}`", &path))
                .expect("can not read file");

            let base_path = path.with_file_name("");

            proto_compiler.include(&base_path);
            proto_parser.include(&base_path);
            proto_compiler.input(&path);
            proto_parser.input(&path);
        }
    }

    // If the YRX_PROTOC_CONFIG_FILE environment variable is set, it must
    // contain the path to a JSON file that indicates additional include
    // directories and input files passed to the `protoc` compiler. The path
    // to the JSON file must be either an absolute path or a path relative to
    // this `build.rs` file.
    //
    // The JSON file must be similar to this:
    //
    // {
    //   "includes": [
    //     "../../vt-protos/protos/tools",
    //     "../../vt-protos/protos"
    //   ],
    //   "inputs": [
    //     "../../vt-protos/protos/titan.proto",
    //     "../../vt-protos/protos/filetypes.proto",
    //     "../../vt-protos/protos/sandbox.proto",
    //     "../../vt-protos/protos/vtnet.proto",
    //     "../../vt-protos/protos/submitter.proto",
    //     "../../vt-protos/protos/analysis.proto",
    //     "../../vt-protos/protos/tools/net_analysis.proto",
    //     "../../vt-protos/protos/tools/snort.proto",
    //     "../../vt-protos/protos/tools/suricata.proto",
    //     "../../vt-protos/protos/tools/tshark.proto",
    //     "../../vt-protos/protos/sigma.proto",
    //     "../../vt-protos/protos/relationships.proto"
    //   ]
    // }
    //
    // Paths in the "includes" and "inputs" lists must also be absolute or
    // relative to this `build.rs` file.
    if let Ok(path) = env::var("YRX_PROTOC_CONFIG_FILE") {
        let file = File::open(path.as_str())
            .unwrap_or_else(|_| panic!("error opening {}", path));

        let reader = BufReader::new(file);
        let config: ProtocConfig = serde_json::from_reader(reader)
            .unwrap_or_else(|_| panic!("invalid config file {}", path));

        for path in config.includes {
            let path = fs::canonicalize(path).unwrap();
            proto_compiler.include(&path);
            proto_parser.include(&path);
        }

        for path in config.inputs {
            let path = fs::canonicalize(path).unwrap();
            proto_compiler.input(&path);
            proto_parser.input(&path);
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
                module_options.cargo_feature,
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
        let cargo_feature = m.3;
        let root_message = m.4;

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

        let cfg_feature = if let Some(cargo_feature) = &cargo_feature {
            format!(r#"#[cfg(feature = "{cargo_feature}")]"#)
        } else {
            "".to_string()
        };

        if let Some(rust_mod) = &rust_mod {
            write!(
                modules_rs,
                r#"
{cfg_feature}
mod {rust_mod};"#,
            )
            .unwrap();
        }

        write!(
            add_modules_rs,
            r#"
{cfg_feature}
add_module!(modules, "{name}", {proto_mod}, "{root_message}", {rust_mod_name}, {main_fn});"#,
        )
            .unwrap();
    }

    write!(add_modules_rs, "}}").unwrap();
}
