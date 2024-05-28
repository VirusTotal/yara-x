use anyhow::Context;
use protobuf::descriptor::FileDescriptorProto;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::{env, fs};

use protobuf_codegen::Codegen;
use protobuf_parse::Parser;

use yara_x_proto::exts::module_options as yara_module_options;

fn generate_module_files(proto_files: Vec<FileDescriptorProto>) {
    let mut modules = Vec::new();
    // Look for .proto files that describe a YARA module. A proto that
    // describes a YARA module has yara.module_options, like...
    //
    // option (yara.module_options) = {
    //   name : "test"
    //   root_message: "Test"
    //   rust_module: "test"
    // };
    //
    for proto_file in proto_files {
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
    let mut modules_rs = match File::create("src/modules/modules.rs") {
        Ok(modules_rs) => modules_rs,
        Err(err) => {
            println!("cargo:warning=`build.rs` was unable to re-generate `lib/src/modules/modules.rs`");
            println!("cargo:warning=due to the following error: {}", err);
            println!("cargo:warning=ignore this warning unless you are trying to add new YARA-X modules");
            println!("cargo:warning=to disable the warning set the environment variable YRX_REGENERATE_MODULES_RS=false");
            return;
        }
    };

    write!(
        modules_rs,
        "// File generated automatically by build.rs. Do not edit."
    )
    .unwrap();

    // Create the add_modules.rs files, with an entry for each proto that
    // defines a YARA module. Each entry looks like:
    //
    //  #[cfg(feature = "foo_module")]
    //  add_module!(modules, "foo", foo, Some(foo::__main__ as MainFn));
    //
    let mut add_modules_rs =
        File::create("src/modules/add_modules.rs").unwrap();

    writeln!(
        add_modules_rs,
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

    write!(add_modules_rs, "\n}}").unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=src/modules");
    println!("cargo:rerun-if-changed=src/modules/protos");

    let mut proto_compiler = Codegen::new();
    let mut proto_parser = Parser::new();

    proto_compiler
        .pure()
        .cargo_out_dir("protos")
        .include("src/modules/protos");

    proto_parser.include("src/modules/protos");

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

    // The environment variable `YRX_EXTRA_PROTOS` allows passing a list of
    // additional `.proto` files with YARA module definitions, in addition to
    // those found in `src/modules/protos`. The value in this variable must be a
    // space-separated list of file paths, and the paths must be either absolute
    // or relative to the location of this `build.rs` file.
    //
    // If you need to provide a list of paths that are relative to some other
    // location in the file system, you can specify a base path using the
    // environment variable `YRX_EXTRA_PROTOS_BASE_PATH`. This base path must be
    // also absolute or relative to the location of this `build.rs`, and the
    // final path for the `.proto` files will be computed by combining the
    // relative paths in `YRX_EXTRA_PROTOS` to the base path. For instance,
    // if you have:
    //
    // YRX_EXTRA_PROTOS_BASE_PATH=../../my/dir
    // YRX_EXTRA_PROTOS="foo.proto bar.proto qux/qux.proto"
    //
    // The final paths will be:
    //
    // ../../my/dir/foo.proto
    // ../../my/dir/bar.proto
    // ../../my/dir/qux/qux.proto
    //
    // All these final paths are relative to this `build.rs` file. Any absolute
    // path in `YRX_EXTRA_PROTOS` is not affected by the base path specified in
    // `YRX_EXTRA_PROTOS_BASE_PATH`, they remain untouched.
    if let Ok(proto_files) = env::var("YRX_EXTRA_PROTOS") {
        for path in proto_files.split(' ').collect::<Vec<_>>() {
            let path = if let Ok(base_path) =
                env::var("YRX_EXTRA_PROTOS_BASE_PATH")
            {
                PathBuf::from(base_path).join(path)
            } else {
                PathBuf::from(path)
            };

            let path = fs::canonicalize(&path)
                .with_context(|| format!("`{:?}`", &path))
                .expect("can not read file");

            println!("cargo:warning=using extra proto: {:?}", &path);

            let base_path = path.with_file_name("");

            proto_compiler.include(&base_path);
            proto_parser.include(&base_path);
            proto_compiler.input(&path);
            proto_parser.input(&path);
        }
    }

    // Generate .rs files for .proto files in src/modules/protos
    proto_compiler.run_from_script();

    // Decide whether the `modules.rs` and `add_modules.rs` files should be
    // re-generated. By default, they will be re-generated.
    let mut regenerate_modules_rs = true;

    // If the environment variable `YRX_REGENERATE_MODULES_RS` is present, the
    // files won't be re-generated if the value is "false", "no" or "0". Any
    // other value will re-generate the files.
    if let Ok(env_var) = env::var("YRX_REGENERATE_MODULES_RS") {
        regenerate_modules_rs =
            env_var != "false" && env_var != "no" && env_var != "0";
    }

    // Also, don't re-generate the files if `DOCS_RS` is defined. This is
    // because doc.rs puts the source code in a read-only file system, and
    // we can't modify the files.
    if env::var("DOCS_RS").is_ok() {
        regenerate_modules_rs = false;
    }

    if regenerate_modules_rs {
        generate_module_files(
            proto_parser.file_descriptor_set().unwrap().file,
        );
    }
}
