/*! YARA module that parses Microsoft Software Installer (MSI) files.

MSI files are OLE Compound Files (CFB) containing installation packages.
This module specializes in validating digital signatures in MSI files.
*/

use crate::errors::ModuleError;
use crate::mods::prelude::*;
use crate::modules::protos::msi::*;
use crate::modules::utils::olecf::CachedOlecf;

pub mod parser;

fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Msi, ModuleError> {
    let cached = ctx.olecf_cache.get_or_insert_with(|| CachedOlecf::new(data));

    let olecf = match cached {
        CachedOlecf::Olecf(olecf) => olecf,
        CachedOlecf::NotOlecf => {
            let mut msi = Msi::new();
            msi.set_is_signed(false);
            return Ok(msi);
        }
    };

    match parser::Msi::parse(olecf) {
        Ok(msi) => Ok(msi),
        Err(_) => {
            let mut msi = Msi::new();
            msi.set_is_signed(false);
            Ok(msi)
        }
    }
}

register_module!("msi", Msi, main);
