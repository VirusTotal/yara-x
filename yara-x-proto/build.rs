use protobuf_codegen::Codegen;

fn main() {
    println!("cargo:rerun-if-changed=src");
    Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .input("src/yara.proto")
        .include("src")
        .run_from_script();
}
