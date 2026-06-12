use protobuf_codegen::Codegen;

fn main() {
    println!("cargo:rerun-if-changed=src");
    Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .input("src/yara.proto")
        .input("src/tests/test_yaml.proto")
        .input("src/tests/test_json.proto")
        .include("src")
        .include("src/tests")
        .run_from_script();
}
