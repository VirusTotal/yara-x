use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn create_binary_from_ihex(ihex: &str) -> Vec<u8> {
    let mut reader = ihex::Reader::new(ihex);
    let mut data = Vec::new();
    while let Some(Ok(record)) = reader.next() {
        if let ihex::Record::Data { value, .. } = record {
            data.extend(value);
        }
    }
    data
}

pub fn create_binary_from_zipped_ihex<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let path = path.as_ref();
    let f = File::open(path)
        .unwrap_or_else(|_| panic!("can not open file: {:?}", &path));

    let mut zip = zip::ZipArchive::new(f)
        .unwrap_or_else(|_| panic!("can not unzip file: {:?}", &path));

    let path_without_zip_ext = path.with_extension("");
    let inner_file_name =
        path_without_zip_ext.file_name().unwrap().to_str().unwrap();

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
}
