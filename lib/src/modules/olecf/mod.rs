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
    
    match parser::OLECFParser::new(data) {
        Ok(parser) => {
            let mut olecf = Olecf::new();
            
            // Check and set is_olecf
            let is_valid = parser.is_valid_header();
            olecf.is_olecf = Some(is_valid);
            
            // Get stream names and sizes
            if let Ok(names) = parser.get_stream_names() {                    
                // Get sizes for each stream
                olecf.stream_sizes = names.iter()
                    .filter_map(|name| {
                        parser.get_stream_size(name)
                            .ok()
                            .map(|size| size as i64)
                    })
                    .collect();
                    
                // Assign names last after we're done using them
                olecf.stream_names = names;
            }
            
            olecf
        },
        Err(_) => {
            let mut olecf = Olecf::new();
            olecf.is_olecf = Some(false);
            olecf
        }
    }
}