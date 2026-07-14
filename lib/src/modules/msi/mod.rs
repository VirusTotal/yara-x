/*! YARA module that parses Microsoft Software Installer (MSI) files.

MSI files are OLE Compound Files (CFB) containing installation packages.
This module specializes in validating digital signatures in MSI files.
*/

use crate::errors::ModuleError;
use crate::mods::prelude::*;
use crate::modules::protos::msi::*;

pub mod parser;

fn main(_ctx: &mut ModuleContext, data: &[u8]) -> Result<Msi, ModuleError> {
    match parser::Msi::parse(data) {
        Ok(msi) => Ok(msi),
        Err(_) => {
            let mut msi = Msi::new();
            msi.set_is_signed(false);
            Ok(msi)
        }
    }
}

register_module!("msi", Msi, main);
