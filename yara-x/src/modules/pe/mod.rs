/*! YARA module that parses PE files.

This allows creating YARA rules based on PE metadata, including sections,
imports and exports, resources, etc.
 */

use crate::modules::prelude::*;
use crate::modules::protos::pe::*;

pub mod parser;

#[module_main]
fn main(ctx: &ScanContext) -> PE {
    match parser::PEParser::new().parse(ctx.scanned_data()) {
        Ok(pe) => pe,
        Err(_) => {
            let mut pe = PE::new();
            pe.is_pe = Some(false);
            pe
        }
    }
}
