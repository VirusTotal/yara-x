use std::fs::File;
use std::io::Read;
use std::path::Path;

use rayon::prelude::*;

/// Utility function that receives the content of an [`Intel HEX`][1] (ihex)
/// file and returns the binary data contained in it.
///
/// All test files in this repository are stored in ihex format in order to
/// avoid storing executable files (some of them malware) in binary form.
///
/// [1]: https://en.wikipedia.org/wiki/Intel_HEX
pub fn create_binary_from_ihex(ihex: &str) -> anyhow::Result<Vec<u8>> {
    let mut reader = ihex::Reader::new(ihex);
    let mut data = Vec::new();
    while let Some(Ok(record)) = reader.next() {
        if let ihex::Record::Data { value, .. } = record {
            data.extend(value);
        }
    }
    Ok(data)
}

/// Utility function that receives a file to a ZIP archive that contains a
/// a compressed [`Intel HEX`][1] (ihex) file and returns the binary data
/// encoded in the ihex file.
pub fn create_binary_from_zipped_ihex<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let path = path.as_ref();

    let f = File::open(path)
        .unwrap_or_else(|_| panic!("can not open file: {:?}", &path));

    let mut zip = zip::ZipArchive::new(f)
        .unwrap_or_else(|_| panic!("can not unzip file: {:?}", &path));

    // The name of the file inside the ZIP must be equal to the name of the
    // ZIP file, but without the .zip extension.
    let path_without_zip_ext = path.with_extension("");
    let inner_file_name =
        path_without_zip_ext.file_name().unwrap().to_str().unwrap();

    // Read the content of the .in file.
    let mut inner_file = zip.by_name(inner_file_name).unwrap_or_else(|_| {
        panic!(
            "ZIP archive {:?} doesn't contain file: {:?}",
            &path, &inner_file_name
        )
    });

    let mut ihex = String::new();

    inner_file.read_to_string(&mut ihex).unwrap_or_else(|_| {
        panic!("can not read ihex content from : {:?}", &path)
    });

    create_binary_from_ihex(ihex.as_str())
        .unwrap_or_else(|_| panic!("invalid ihex content in: {:?}", &path))
}

/// This function tests YARA modules by comparing the output produced by the
/// module with a golden file that contains the expected output.
///
/// The function walks the  directory looking for files with extension
/// `*.in.zip`. These files can contain arbitrary binary content, but they
/// must be encoded in the [`Intel HEX format`][1], which is a text
/// representation of the original content, and then compressed with ZIP.
/// Storing binary files in our source repository is not a good idea,
/// specially if such files are executable files containing malware.
///
/// Each `*.in.zip` ZIP archive must contain a single file with the same
/// name as the ZIP archive, but without the `.zip` extension. For
/// instance, an archive named `foo.in.zip` must contain a file named
/// `foo.in`. The `.in` files (encoded in IHEX format) are decoded and then
/// passed to the corresponding module, which is determined by looking at
/// the path where the file was found. If the file is found anywhere under
/// a directory named `yara-x/src/modules/foo`, its content is passed as
/// input to the `foo` module. Then, the output produced by the module is
/// compared with the content of a `*.out` file that is expected to have
/// the same name as the `*.in.zip` file.
///
/// To pass metadata to the module, also include a file with the same name
/// as the `.in.zip` file, but with the `.in.metadata.zip` extension. The
/// format of this file must be the same as the `.in.zip` file, i.e. it must
/// contain a single `<name>.in` file encoded in the IHEX format.
/// The content of this file is passed as metadata to the module.
///
/// There are many tools for converting binary files to Intel HEX format, one
/// of such tools is `objcopy` (`llvm-objcopy` on Mac OS X).
///
/// ```text
/// objcopy -I binary -O ihex foo foo.in
/// ```
///
/// For compressing the files:
///
/// ```text
/// zip foo.in.zip foo.in
/// ```
///
/// [1]: https://en.wikipedia.org/wiki/Intel_HEX
#[test]
fn test_modules() {
    // Create goldenfile mint.
    let files: Vec<_> = globwalk::glob("src/modules/**/*.in.zip")
        .unwrap()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    files.into_par_iter().for_each(|path| {
        let mut mint = goldenfile::Mint::new(".");

        // Read the data encoded in the .in.zip file.
        let data = create_binary_from_zipped_ihex(&path);

        // if there is some metadata, it should be in same_name.in.metadata.zip file
        let metadata_path =
            path.with_extension("").with_extension("in.metadata.zip");

        let meta = metadata_path
            .exists()
            .then(|| create_binary_from_zipped_ihex(&metadata_path));

        // Path to the .out file. First remove the .zip extension, then replace
        // the .in extension with .out.
        let out_path = path.with_extension("").with_extension("out");

        // The name of module being tested is extracted from the path, which
        // should have the form src/modules/<module name>/....
        let module_name = path
            .components()
            .nth(3)
            .map(|s| s.as_os_str().to_str().unwrap())
            .expect("can not extract module name from tests path");

        // Construct a dummy YARA rule that only imports the module.
        let rule = format!(
            r#"import "{}" rule test {{ condition: false }}"#,
            module_name
        );

        // Compile the rule.
        let rules = crate::compile(rule.as_str()).unwrap();
        let mut scanner = crate::scanner::Scanner::new(&rules);

        let options = match meta {
            Some(ref meta) => crate::scanner::ScanOptions::new()
                .set_module_metadata(module_name, meta),
            None => crate::scanner::ScanOptions::new(),
        };

        // Scan the data.
        let scan_results = scanner
            .scan_with_options(&data, options)
            .expect("scan should not fail");

        // Get the module output.
        let output =
            scan_results.module_output(module_name).unwrap_or_else(|| {
                panic!("module `{}` should produce some output", module_name)
            });

        let output_file = mint.new_goldenfile(out_path).unwrap();

        // Render the module's output as YAML.
        let mut yaml = yara_x_proto_yaml::Serializer::new(output_file);

        yaml.serialize(output).unwrap();
    });
}
