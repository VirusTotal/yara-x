fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto");

    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .include("proto")
        .input("proto/foobar.proto")
        .run_from_script();
}
