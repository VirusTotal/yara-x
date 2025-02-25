/*! YARA module that parses OLE Compound File Binary Format files.

The OLE CF format (also known as Compound File Binary Format or CFBF) is a
container format used by many Microsoft file formats including DOC, XLS, PPT,
and MSI. This module specializes in parsing OLE CF files and extracting
metadata about their structure and contents.

Read more about the Compound File Binary File format here:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
*/

use crate::modules::prelude::*;
use crate::modules::protos::olecf::*;

pub mod parser;

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Olecf {
    let mut olecf = Olecf::new();

    match parser::OLECFParser::new(data) {
        Ok(parser) => {
            olecf.set_is_olecf(parser.is_valid_header());
            olecf.streams = parser
                .get_streams()
                .map(|(name, entry)| {
                    let mut s = Stream::new();
                    s.set_name(name.to_string());
                    s.set_size(entry.size);
                    s
                })
                .collect();
        }
        Err(_) => {
            olecf.set_is_olecf(false);
        }
    }

    olecf
}
