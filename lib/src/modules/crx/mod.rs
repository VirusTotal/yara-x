/*! YARA module that parses Chrome Browser Extension (CRX) files.

This allows creating YARA rules based on metadata extracted from those files.
 */

mod parser;

use crate::modules::crx::Crx;
use crate::modules::prelude::*;
use crate::modules::protos::crx::*;

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<Crx, ModuleError> {
    match parser::Crx::parse(data) {
        Ok(crx) => Ok(crx.into()),
        Err(_) => {
            let mut crx = Crx::new();
            crx.set_is_crx(false);
            Ok(crx)
        }
    }
}
