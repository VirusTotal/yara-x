/*! YARA module that parses ELF files.

This allows creating YARA rules based on ELF metadata, including segments
and sections information, exported symbols, target platform, etc.
 */

use std::cell::RefCell;
use std::sync::LazyLock;

use itertools::Itertools;
use md5::{Digest, Md5};
use rustc_hash::FxHashSet;

use crate::modules::prelude::*;
use crate::modules::protos::elf::*;

pub mod parser;

#[cfg(test)]
mod tests;
mod tlsh;

thread_local!(
    static IMPORT_MD5_CACHE: RefCell<Option<String>> =
        const { RefCell::new(None) };
    static TLSH_CACHE: RefCell<Option<String>> = const { RefCell::new(None) };
);

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> Result<ELF, ModuleError> {
    IMPORT_MD5_CACHE.with(|cache| *cache.borrow_mut() = None);
    TLSH_CACHE.with(|cache| *cache.borrow_mut() = None);

    match parser::ElfParser::new().parse(data) {
        Ok(elf) => Ok(elf),
        Err(_) => Ok(ELF::new()),
    }
}

#[module_export]
fn import_md5(ctx: &mut ScanContext) -> Option<Lowercase<FixedLenString<32>>> {
    let cached = IMPORT_MD5_CACHE.with(
        |cache| -> Option<Lowercase<FixedLenString<32>>> {
            cache.borrow().as_deref().map(|s| {
                Lowercase::<FixedLenString<32>>::from_slice(ctx, s.as_bytes())
            })
        },
    );

    if cached.is_some() {
        return cached;
    }

    let elf = ctx.module_output::<ELF>()?;

    let symbols = if elf.dynsym.is_empty() {
        elf.symtab.iter()
    } else {
        elf.dynsym.iter()
    };

    let comma_separated_names = symbols
        .filter_map(|sym| match (sym.shndx, sym.name.as_ref()) {
            (Some(shndx), Some(name)) if shndx == 0 && !name.is_empty() => {
                Some(name.to_lowercase())
            }
            _ => None,
        })
        .sorted()
        .join(",");

    let mut hasher = Md5::new();
    hasher.update(comma_separated_names.as_bytes());

    let digest = format!("{:x}", hasher.finalize());

    IMPORT_MD5_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(digest.clone());
    });

    Some(Lowercase::<FixedLenString<32>>::new(digest))
}

/// Function names excluded while computing the telfhash. These exclusions
/// are based on the original implementation:
/// https://github.com/trendmicro/telfhash/blob/master/telfhash/telfhash.py
pub(crate) static TELFHASH_EXCLUSIONS: LazyLock<FxHashSet<&'static str>> =
    LazyLock::new(|| {
        let mut exclusions = FxHashSet::default();
        exclusions.insert("__libc_start_main");
        exclusions.insert("main");
        exclusions.insert("abort");
        exclusions.insert("cachectl");
        exclusions.insert("cacheflush");
        exclusions.insert("puts");
        exclusions.insert("atol");
        exclusions.insert("malloc_trim");
        exclusions
    });

/// Function that returns the [`telfhash`][1] for the current ELF file.
///
/// `telfhash` is a symbol hash for ELF files, just like `imphash` is imports
/// hash for PE files. With `telfhash`, you can cluster ELF files by similarity
/// based on symbols.
///
/// [1]: https://github.com/trendmicro/telfhash
#[module_export]
fn telfhash(ctx: &mut ScanContext) -> Option<Uppercase<FixedLenString<72>>> {
    let cached =
        TLSH_CACHE.with(|cache| -> Option<Uppercase<FixedLenString<72>>> {
            cache.borrow().as_deref().map(|s| {
                Uppercase::<FixedLenString<72>>::from_slice(ctx, s.as_bytes())
            })
        });

    if cached.is_some() {
        return cached;
    }

    let elf = ctx.module_output::<ELF>()?;

    // Prefer dynsym over symbtab.
    let symbols = if elf.dynsym.is_empty() {
        elf.symtab.iter()
    } else {
        elf.dynsym.iter()
    };

    let comma_separated_names = symbols
        .filter_map(|sym| {
            if sym.type_?.enum_value().ok()? != SymType::STT_FUNC {
                return None;
            }

            if sym.bind?.enum_value().ok()? != SymBind::STB_GLOBAL {
                return None;
            }

            if sym.visibility?.enum_value().ok()? != SymVisibility::STV_DEFAULT
            {
                return None;
            }

            let name = sym.name.as_ref()?;

            if TELFHASH_EXCLUSIONS.contains(name.as_str())
                || name.starts_with('.')
                || name.starts_with('_')
                || name.starts_with("mem")
                || name.starts_with("str")
                || name.ends_with("64")
            {
                return None;
            }

            Some(name.to_lowercase())
        })
        .sorted()
        .join(",");

    let mut builder = tlsh::TlshBuilder::new(
        tlsh::BucketKind::Bucket128,
        tlsh::ChecksumKind::OneByte,
        tlsh::Version::Version4,
    );

    builder.update(comma_separated_names.as_bytes());

    let digest = builder.build().ok()?.hash();

    IMPORT_MD5_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(digest.clone());
    });

    Some(Uppercase::<FixedLenString<72>>::new(digest))
}
