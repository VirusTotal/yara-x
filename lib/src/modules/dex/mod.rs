/*! YARA module that parses Dalvik Executable Formats (DEX) files

This allows creating YARA rules based on metadata extracted from those files.
 */

use crate::modules::prelude::*;
use crate::modules::protos::dex::*;

pub mod parser;

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Dex, ModuleError> {
    match parser::Dex::parse(data) {
        Ok(dex) => Ok(dex.into()),
        Err(_) => {
            let mut dex = Dex::new();
            dex.set_is_dex(false);
            Ok(dex)
        }
    }
}
