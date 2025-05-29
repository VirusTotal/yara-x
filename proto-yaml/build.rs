use protobuf_codegen::Codegen;

fn main() {
    println!("cargo:rerun-if-changed=src");
    Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .include("../proto/src")
        .include("src/tests")
        .include("src")
        .input("src/tests/test.proto")
        .input("../proto/src/yara.proto")
        .run_from_script();
}
