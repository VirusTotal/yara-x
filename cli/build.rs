use vcpkg;

fn main() {
    println!("cargo:rerun-if-changed=src");

    vcpkg::find_package("libmagic").unwrap();
    vcpkg::find_package("bzip2").unwrap();
    vcpkg::find_package("zlib").unwrap();
}
