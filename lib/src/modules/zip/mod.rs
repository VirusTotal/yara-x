use crate::mods::prelude::*;
use crate::modules::ModuleError;
use crate::modules::protos::zip::Zip;
use crate::modules::utils::zip::ZipCache;
use crate::register_module;

pub fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Zip, ModuleError> {
    match ctx.zip_cache.get_or_insert_with(|| ZipCache::new(data)) {
        ZipCache::Cached(zip) => Ok(zip.proto.clone()),
        ZipCache::NotAZip => {
            let mut zip = Zip::new();
            zip.set_is_zip(false);
            Ok(zip)
        }
    }
}

register_module!("zip", Zip, main);
