#[cfg(feature = "generate-proto-code")]
use protobuf::descriptor::FileDescriptorProto;

#[cfg(feature = "generate-proto-code")]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
struct Module {
    name: String,
    proto_mod: String,
    rust_mod: Option<String>,
    cargo_feature: Option<String>,
    root_msg: String,
}

#[cfg(feature = "generate-proto-code")]
fn generate_module_files(proto_files: &[FileDescriptorProto]) -> Vec<Module> {
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use yara_x_proto::exts::module_options as yara_module_options;

    println!("cargo:rerun-if-changed=src/modules/modules.rs");

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
            let proto_path = PathBuf::from(proto_file.name.as_ref().unwrap());
            let proto_name = proto_path
                .with_extension("")
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            let root_msg = module_options.root_message.unwrap();

            modules.push(Module {
                name: module_options.name.unwrap(),
                proto_mod: proto_name,
                rust_mod: module_options.rust_module,
                cargo_feature: module_options.cargo_feature,
                root_msg,
            });
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
            println!(
                "cargo:warning=`build.rs` was unable to re-generate `lib/src/modules/modules.rs`"
            );
            println!("cargo:warning=due to the following error: {err}");
            println!(
                "cargo:warning=ignore this warning unless you are trying to add new YARA-X modules"
            );
            println!(
                "cargo:warning=to disable the warning set the environment variable YRX_REGENERATE_MODULES_RS=false"
            );
            return Vec::new();
        }
    };

    write!(
        modules_rs,
        "// File generated automatically by build.rs. Do not edit."
    )
    .unwrap();

    // Sort modules by name, so that they always appear in the same order
    // no matter the platform. If modules are not sorted, the order will
    // vary from one platform to the other, in the same way that HashMap
    // doesn't produce consistent key order.
    modules.sort_by(|a, b| a.name.cmp(&b.name));

    for m in &modules {
        let rust_mod = &m.rust_mod;
        let cargo_feature = &m.cargo_feature;

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
    }

    modules
}

#[cfg(feature = "generate-module-docs")]
fn generate_module_docs(
    proto_files: &[FileDescriptorProto],
    modules: &[Module],
) {
    use std::collections::{HashMap, HashSet};
    use std::fs::File;
    use std::io::Write;

    // 1. Collect message dependencies
    let mut dependencies = HashMap::new();

    for proto_file in proto_files {
        let package = proto_file.package.as_deref().unwrap_or("");

        fn collect_deps(
            msg: &protobuf::descriptor::DescriptorProto,
            full_name: String,
            deps: &mut HashMap<String, Vec<String>>,
        ) {
            let mut referenced = Vec::new();
            for field in &msg.field {
                if field.type_()
                    == protobuf::descriptor::field_descriptor_proto::Type::TYPE_MESSAGE
                {
                    if let Some(type_name) = &field.type_name {
                        let dep_name = type_name
                            .strip_prefix('.')
                            .unwrap_or(type_name)
                            .to_string();
                        referenced.push(dep_name);
                    }
                }
            }

            for nested in &msg.nested_type {
                let nested_name = format!(
                    "{}.{}",
                    full_name,
                    nested.name.as_deref().unwrap_or("")
                );
                collect_deps(nested, nested_name, deps);
            }

            deps.insert(full_name, referenced);
        }

        for msg in &proto_file.message_type {
            let msg_name = msg.name.as_deref().unwrap_or("");
            let full_name = if package.is_empty() {
                msg_name.to_string()
            } else {
                format!("{}.{}", package, msg_name)
            };
            collect_deps(msg, full_name, &mut dependencies);
        }
    }

    // 2. Compute transitive closure
    let mut reachable = HashSet::new();
    let mut queue: Vec<String> = Vec::new();

    for m in modules {
        let root = &m.root_msg;
        if reachable.insert(root.clone()) {
            queue.push(root.clone());
        }
    }

    while let Some(node) = queue.pop() {
        if let Some(deps) = dependencies.get(&node) {
            for dep in deps {
                if reachable.insert(dep.clone()) {
                    queue.push(dep.clone());
                }
            }
        }
    }

    // 3. Generate docs only for reachable messages
    let mut docs = Vec::new();

    for proto_file in proto_files {
        let package = proto_file.package.as_deref().unwrap_or("");
        let mut msg_map = HashMap::new();

        // Recursively traverse messages to build a map of paths to message names and field numbers.
        fn traverse_msg(
            msg: &protobuf::descriptor::DescriptorProto,
            path: Vec<i32>,
            full_name: String,
            map: &mut HashMap<Vec<i32>, (String, Vec<u64>)>,
        ) {
            let mut field_numbers = Vec::new();
            for field in &msg.field {
                field_numbers.push(field.number.unwrap_or(0) as u64);
            }
            map.insert(path.clone(), (full_name.clone(), field_numbers));

            for (k, nested) in msg.nested_type.iter().enumerate() {
                let mut nested_path = path.clone();
                nested_path.push(3); // 3 is nested_type in DescriptorProto
                nested_path.push(k as i32);
                let nested_name = format!(
                    "{}.{}",
                    full_name,
                    nested.name.as_deref().unwrap_or("")
                );
                traverse_msg(nested, nested_path, nested_name, map);
            }
        }

        for (i, msg) in proto_file.message_type.iter().enumerate() {
            let msg_name = msg.name.as_deref().unwrap_or("");
            let full_name = if package.is_empty() {
                msg_name.to_string()
            } else {
                format!("{}.{}", package, msg_name)
            };
            traverse_msg(msg, vec![4, i as i32], full_name, &mut msg_map);
        }

        let source_code_info_ref = proto_file.source_code_info.as_ref();
        let source_code_info = match source_code_info_ref {
            Some(info) => info,
            None => continue,
        };

        for location in &source_code_info.location {
            let path = &location.path;
            if path.len() >= 2 && path[path.len() - 2] == 2 {
                let field_idx = path[path.len() - 1] as usize;
                let msg_path = &path[..path.len() - 2];

                if let Some((msg_name, field_numbers)) = msg_map.get(msg_path)
                {
                    if reachable.contains(msg_name)
                        && field_idx < field_numbers.len()
                    {
                        let field_number = field_numbers[field_idx];
                        if let Some(comments) = &location.leading_comments {
                            docs.push((
                                msg_name.clone(),
                                field_number,
                                comments.trim().to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    docs.sort();

    let mut field_docs_rs = File::create("src/modules/field_docs.rs").unwrap();

    writeln!(
        field_docs_rs,
        "// File generated automatically by build.rs. Do not edit.\n"
    )
    .unwrap();

    writeln!(field_docs_rs, "pub const FIELD_DOCS: &[(&str, u64, &str)] = &[")
        .unwrap();

    for (msg_name, field_number, comments) in docs {
        let escaped_comments = comments.replace("\"", "\\\"");
        writeln!(
            field_docs_rs,
            r#"    ("{}", {}, "{}"),"#,
            msg_name, field_number, escaped_comments
        )
        .unwrap();
    }

    writeln!(field_docs_rs, "];").unwrap();
}

#[cfg(feature = "generate-proto-code")]
fn generate_proto_code() {
    use anyhow::Context;
    use std::path::PathBuf;
    use std::{env, fs};

    use protobuf_codegen::Codegen;
    use protobuf_parse::Parser;

    let mut proto_compiler = Codegen::new();
    let mut proto_parser = Parser::new();

    if cfg!(feature = "protoc") {
        proto_compiler.protoc();
        proto_parser.protoc();

        #[cfg(feature = "generate-module-docs")]
        proto_parser.protoc_extra_args(["--include_source_info"]);
    } else {
        proto_compiler.pure();
        proto_parser.pure();
    }

    println!("cargo:rerun-if-changed=src/modules/protos");

    proto_compiler.cargo_out_dir("protos").include("./src/modules/protos");
    proto_parser.include("./src/modules/protos");

    // All `.proto` files in src/modules/protos must be compiled
    for entry in globwalk::glob("src/modules/protos/**").unwrap().flatten() {
        let path = entry.path();
        if entry.metadata().unwrap().is_dir() {
            proto_compiler.include(path);
            proto_parser.include(path);
        }
        if let Some(extension) = path.extension()
            && extension == "proto"
        {
            proto_compiler.input(path);
            proto_parser.input(path);
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

    // Decide whether `modules.rs` and the content of the `protos/generated`
    // directory should be re-generated. By default, they will be re-generated.
    let mut regenerate = true;

    // If the environment variable `YRX_REGENERATE_MODULES_RS` is present, the
    // files won't be re-generated if the value is "false", "no" or "0". Any
    // other value will re-generate the files.
    if let Ok(env_var) = env::var("YRX_REGENERATE_MODULES_RS") {
        regenerate = env_var != "false" && env_var != "no" && env_var != "0";
    }

    // Also, don't re-generate the files if `DOCS_RS` is defined. This is
    // because doc.rs puts the source code in a read-only file system, and
    // we can't modify the files.
    if env::var("DOCS_RS").is_ok() {
        regenerate = false;
    }

    if regenerate {
        let proto_files = proto_parser.file_descriptor_set().unwrap().file;

        #[allow(unused_variables)]
        let modules = generate_module_files(&proto_files);

        #[cfg(feature = "generate-module-docs")]
        generate_module_docs(&proto_files, &modules);

        let out_dir = env::var("OUT_DIR").unwrap();
        let src_dir = PathBuf::from("src/modules/protos/generated");
        let _ = fs::create_dir_all(&src_dir);

        for entry in globwalk::glob(format!("{}/protos/*.rs", out_dir))
            .unwrap()
            .flatten()
        {
            let path = entry.path();
            let file_name = path.file_name().unwrap();
            let dest = src_dir.join(file_name);
            fs::copy(path, dest).unwrap();
        }
    }
}

fn main() {
    #[cfg(feature = "generate-proto-code")]
    generate_proto_code();
}
