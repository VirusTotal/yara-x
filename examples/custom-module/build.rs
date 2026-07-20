fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto");

    let out_dir = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").expect("OUT_DIR must be set"),
    );
    let yara_proto_dir = out_dir.join("yara-proto");
    std::fs::create_dir_all(&yara_proto_dir)
        .expect("failed to create yara.proto include directory");
    std::fs::write(
        yara_proto_dir.join(yara_x_proto::YARA_PROTO_FILE_NAME),
        yara_x_proto::YARA_PROTO,
    )
    .expect("failed to write yara.proto");
    let yara_proto_path =
        yara_proto_dir.join(yara_x_proto::YARA_PROTO_FILE_NAME);

    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .include("proto")
        .include(yara_proto_dir)
        .input(yara_proto_path)
        .input("proto/foobar.proto")
        .run_from_script();
}
