use protobuf_codegen::Codegen;

fn main() {
    Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .include("src/tests/protos")
        .input("src/tests/protos/dumper.proto")
        .input("src/tests/protos/test.proto")
        .run_from_script();
}
