/*! YARA module that parses OLE Compound File Binary Format files.

The OLE CF format (also known as Compound File Binary Format or CFBF) is a
container format used by many Microsoft file formats including DOC, XLS, PPT,
and MSI. This module specializes in parsing OLE CF files and extracting
metadata about their structure and contents.

Read more about the Compound File Binary File format here:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
*/

use crate::errors::ModuleError;
use crate::mods::prelude::*;
use crate::modules::protos::olecf::*;
use crate::modules::utils::olecf::CachedOlecf;

pub mod parser;

#[cfg(test)]
mod tests;

fn main<'a>(
    ctx: &mut ModuleContext<'a>,
    data: &'a [u8],
) -> Result<Olecf, ModuleError> {
    let cached = ctx.olecf_cache.get_or_insert_with(|| CachedOlecf::new(data));
    let mut olecf = Olecf::new();

    let cached = match cached {
        CachedOlecf::Olecf(olecf) => olecf,
        CachedOlecf::NotOlecf => {
            olecf.set_is_olecf(false);
            return Ok(olecf);
        }
    };

    olecf.set_is_olecf(cached.is_valid_header());

    olecf.streams = cached
        .streams()
        .map(|(name, entry)| {
            let mut s = Stream::new();
            s.set_name(name.to_string());
            s.set_size(entry.size);
            s.set_type(match entry.stream_type {
                parser::DirEntryType::Storage => StreamType::STORAGE,
                parser::DirEntryType::Stream => StreamType::STREAM,
                parser::DirEntryType::RootStorage => StreamType::ROOT,
                _ => StreamType::UNKNOWN,
            });
            s
        })
        .collect();

    Ok(olecf)
}

register_module!("olecf", Olecf, main);
