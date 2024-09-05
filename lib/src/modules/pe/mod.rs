/*! YARA module that parses PE files.

This allows creating YARA rules based on PE metadata, including sections,
imports and exports, resources, etc.
 */

use std::rc::Rc;
use std::slice::Iter;

use bstr::BStr;
use digest::Digest;
use itertools::Itertools;
use nom::branch::alt;
use nom::character::complete::u8;
use nom::combinator::map;
use nom::number::complete::{le_u16, le_u32};

use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::pe::*;
use crate::types::Struct;

#[cfg(test)]
mod tests;

mod asn1;
mod authenticode;
pub mod parser;
mod rva2off;

#[module_main]
fn main(data: &[u8], _meta: Option<&[u8]>) -> PE {
    match parser::PE::parse(data) {
        Ok(pe) => pe.into(),
        Err(_) => {
            let mut pe = PE::new();
            pe.is_pe = Some(false);
            pe
        }
    }
}

/// Returns true if the file is a 32-bit PE.
#[module_export]
fn is_32bit(ctx: &ScanContext) -> Option<bool> {
    let magic = ctx.module_output::<PE>()?.opthdr_magic?;
    Some(magic.value() == OptionalMagic::IMAGE_NT_OPTIONAL_HDR32_MAGIC as i32)
}

/// Returns true if the file is a 64-bit PE.
#[module_export]
fn is_64bit(ctx: &ScanContext) -> Option<bool> {
    let magic = ctx.module_output::<PE>()?.opthdr_magic?;
    Some(magic.value() == OptionalMagic::IMAGE_NT_OPTIONAL_HDR64_MAGIC as i32)
}

/// Returns true if the file is dynamic link library (DLL)
#[module_export]
fn is_dll(ctx: &ScanContext) -> Option<bool> {
    let characteristics = ctx.module_output::<PE>()?.characteristics?;
    Some(characteristics & Characteristics::DLL as u32 != 0)
}

/// Convert a relative virtual address (RVA) to a file offset.
#[module_export]
fn rva_to_offset(ctx: &ScanContext, rva: i64) -> Option<i64> {
    let pe = ctx.module_output::<PE>()?;
    let offset = rva2off::rva_to_offset(
        rva.try_into().ok()?,
        pe.sections.as_slice(),
        pe.file_alignment?,
        pe.section_alignment?,
    )?;
    Some(offset.into())
}

/// Returns the PE checksum, as calculated by YARA.
///
/// This is useful for comparing with the checksum appearing in the PE header
/// (pe.checksum) in order to verify if the actual checksum matches the one
/// in the header.
#[module_export]
fn calculate_checksum(ctx: &mut ScanContext) -> Option<i64> {
    // In essence, the checksum algorithm goes as follows:
    //
    // - Read the file as a series of 16-bit little-endian unsigned integers.
    //   Pad with zeroes if necessary.
    // - Use a 16-bit accumulator to add up the integers. For each sum, if a
    //   carry is generated, add it to the accumulator.
    // - During computation, ignore the 4 bytes in the PE optional header where
    //   the checksum is stored, as the checksum cannot include itself.
    // - Add the resulting 16-bit sum to the file size to obtain the final
    //   checksum.
    //
    // However, for performance optimization, the algorithm can be adapted to
    // work with 32-bit integers. The computation remains the same, but the
    // resulting 32-bit sum is folded into 16-bits by adding the high and
    // the low parts together. If this addition produces a carry, it's also
    // added to the final sum.
    //
    // To ignore the 4 bytes in the header containing the checksum, some
    // implementations (namely pefile) track file's position and skip it if
    // matches the position where the checksum is stored. The current
    // implementation takes a different approach; it computes the checksum
    // for the entire file, including the header checksum. To account for this
    // inclusion, it then compensates by subtracting the checksum value in the
    // header from the computed checksum. This trick was used in the original
    // Microsoft code:
    //
    // https://bytepointer.com/resources/microsoft_pe_checksum_algo_distilled.htm
    //
    // In fact, pefile's implementation is broken for files where the checksum
    // in the header is not aligned to a 4-bytes boundary. Such files are not
    // very common, but they do exist. Example:
    // af3f20a9272489cbef4281c8c86ad42ccfb04ccedd3ada1e8c26939c726a4c8e
    let pe = ctx.module_output::<PE>()?;
    let data = ctx.scanned_data();
    let mut sum: u32 = 0;

    if !pe.is_pe() {
        return None;
    }

    // The parser first try to read an u32, if not enough data is available,
    // it tries to read an u16, and if still there's no data available it
    // tries to read a byte. In all cases the result is promoted to u32. This
    // emulates the padding at the end of the data if necessary.
    let data_parser = alt((
        le_u32::<&[u8], nom::error::Error<&[u8]>>,
        map(le_u16, |v| v as u32),
        map(u8, |v| v as u32),
    ));

    for v in &mut nom::combinator::iterator(data, data_parser) {
        // TODO: use carrying_add when it becomes stable.
        // This:
        //   sum = match sum.overflowing_add(v) {
        //      (s, true) => s + 1,
        //      (s, false) => s,
        //   }
        // Becomes this:
        //   (sum, carry) = sum.carrying_add(v, carry);
        //
        // Where `carry` must be initialized to false outside of the loop.
        sum = match sum.overflowing_add(v) {
            (s, true) => s + 1, // carry
            (s, false) => s,    // no carry
        }
    }

    sum = match sum.overflowing_sub(pe.checksum?) {
        (s, true) => s - 1, // borrow
        (s, false) => s,    // no borrow
    };

    sum = (sum & 0xffff) + (sum >> 16);
    sum += sum >> 16;
    sum &= 0xffff;
    sum += data.len() as u32;

    Some(sum.into())
}

/// Returns the index in the section table of the first section with the given
/// name.
#[module_export(name = "section_index")]
fn section_index_name(ctx: &ScanContext, name: RuntimeString) -> Option<i64> {
    let pe = ctx.module_output::<PE>()?;
    let name = name.as_bstr(ctx);

    pe.sections
        .iter()
        .find_position(|section| {
            section.name.as_deref().is_some_and(|n| n == name.as_bytes())
        })
        .map(|(index, _)| index as i64)
}

/// Returns the index in the section table of the first section that contains
/// the given file offset.
#[module_export(name = "section_index")]
fn section_index_offset(ctx: &ScanContext, offset: i64) -> Option<i64> {
    let pe = ctx.module_output::<PE>()?;
    let offset: u32 = offset.try_into().ok()?;

    pe.sections
        .iter()
        .find_position(|section| {
            match (section.raw_data_offset, section.raw_data_size) {
                (Some(section_offset), Some(section_size)) => (section_offset
                    ..section_offset + section_size)
                    .contains(&offset),
                _ => false,
            }
        })
        .map(|(index, _)| index as i64)
}

/// Returns the PE import hash.
///
/// The import hash represents the MD5 checksum of the PE's import table
/// following a normalization process. PE files sharing the same import hash
/// import precisely identical functions from the same DLLs. This characteristic
/// often signifies file similarity, despite not being byte-for-byte identical.
/// For additional details, refer to:
/// https://www.mandiant.com/resources/blog/tracking-malware-import-hashing
///
/// The resulting hash string is consistently in lowercase.
#[module_export]
fn imphash(ctx: &mut ScanContext) -> Option<RuntimeString> {
    let pe = ctx.module_output::<PE>()?;

    if !pe.is_pe() {
        return None;
    }

    let mut md5_hash = md5::Md5::default();
    let mut first = true;

    for import in &pe.import_details {
        let original_dll_name =
            import.library_name.as_deref().unwrap().to_lowercase();
        let mut dll_name = original_dll_name.as_str();
        // If extension is '.dll', '.sys' or '.ocx', remove it.
        for extension in [".dll", ".sys", ".ocx"] {
            dll_name = dll_name.trim_end_matches(extension);
        }
        for func in &import.functions {
            if !first {
                Digest::update(&mut md5_hash, ",".as_bytes())
            }
            Digest::update(&mut md5_hash, dll_name);
            Digest::update(&mut md5_hash, ".".as_bytes());
            Digest::update(
                &mut md5_hash,
                func.name.as_deref().unwrap().to_lowercase().as_bytes(),
            );
            first = false;
        }
    }

    let digest = format!("{:x}", md5_hash.finalize());
    Some(RuntimeString::new(digest))
}

#[module_export(name = "rich_signature.toolid")]
fn rich_toolid(ctx: &mut ScanContext, toolid: i64) -> Option<i64> {
    rich_version_impl(ctx.module_output::<PE>()?, Some(toolid), None)
}

#[module_export(name = "rich_signature.version")]
fn rich_version(ctx: &mut ScanContext, version: i64) -> Option<i64> {
    rich_version_impl(ctx.module_output::<PE>()?, None, Some(version))
}

#[module_export(name = "rich_signature.version")]
fn rich_version_toolid(
    ctx: &mut ScanContext,
    version: i64,
    toolid: i64,
) -> Option<i64> {
    rich_version_impl(ctx.module_output::<PE>()?, Some(toolid), Some(version))
}

#[module_export(name = "rich_signature.toolid")]
fn rich_toolid_version(
    ctx: &mut ScanContext,
    toolid: i64,
    version: i64,
) -> Option<i64> {
    rich_version_impl(ctx.module_output::<PE>()?, Some(toolid), Some(version))
}

fn rich_version_impl(
    pe: &PE,
    toolid: Option<i64>,
    version: Option<i64>,
) -> Option<i64> {
    assert!(toolid.is_some() || version.is_some());

    let count = pe
        .rich_signature
        .tools
        .iter()
        .filter_map(|t| {
            let toolid_matches = toolid
                .map(|toolid| toolid == t.toolid.unwrap() as i64)
                .unwrap_or(true);

            let version_matches = version
                .map(|version| version == t.version.unwrap() as i64)
                .unwrap_or(true);

            if toolid_matches && version_matches {
                t.times.map(|v| v as i64)
            } else {
                None
            }
        })
        .sum::<i64>();

    Some(count)
}

/// Returns the number of functions imported by the PE from `dll_name`.
///
/// `dll_name` is case-insensitive.
#[module_export(name = "imports")]
fn standard_imports_dll(
    ctx: &ScanContext,
    dll_name: RuntimeString,
) -> Option<i64> {
    imports_impl(
        ctx,
        ImportFlags::IMPORT_STANDARD as i64,
        MatchCriteria::Name(dll_name.as_bstr(ctx)),
        MatchCriteria::Any,
    )
}

/// Returns true if the PE imports `func_name` from `dll_name`.
///
/// Both `func_name` and `dll_name` are case-insensitive.
#[module_export(name = "imports")]
fn standard_imports_func(
    ctx: &ScanContext,
    dll_name: RuntimeString,
    func_name: RuntimeString,
) -> Option<bool> {
    Some(
        imports_impl(
            ctx,
            ImportFlags::IMPORT_STANDARD as i64,
            MatchCriteria::Name(dll_name.as_bstr(ctx)),
            MatchCriteria::Name(func_name.as_bstr(ctx)),
        )? > 0,
    )
}

/// Returns true if the PE imports `ordinal` from `dll_name`.
///
/// `dll_name` is case-insensitive.
#[module_export(name = "imports")]
fn standard_imports_ordinal(
    ctx: &ScanContext,
    dll_name: RuntimeString,
    ordinal: i64,
) -> Option<i64> {
    imports_impl(
        ctx,
        ImportFlags::IMPORT_STANDARD as i64,
        MatchCriteria::Name(dll_name.as_bstr(ctx)),
        MatchCriteria::Ordinal(ordinal),
    )
}

/// Returns the number of imported functions where the function's name matches
/// `func_name` and the DLL name matches `dll_name`.
///
/// Both `dll_name` and `func_name` are case-sensitive unless you use the "/i"
/// modifier in the regexp, as shown in the example below.
#[module_export(name = "imports")]
fn standard_imports_regexp(
    ctx: &ScanContext,
    dll_name: RegexpId,
    func_name: RegexpId,
) -> Option<i64> {
    imports_impl(
        ctx,
        ImportFlags::IMPORT_STANDARD as i64,
        MatchCriteria::Regexp(dll_name),
        MatchCriteria::Regexp(func_name),
    )
}

/// Returns the number of functions imported by the PE from `dll_name`.
///
/// `dll_name` is case-insensitive. `import_flags` specify the types of
/// import which should be taken into account. This value can be composed
/// by a bitwise OR of the following values:
///
/// * `pe.IMPORT_STANDARD` : standard import only
/// * `pe.IMPORT_DELAYED` : delayed imports only
/// * `pe.IMPORT_ANY` : both standard and delayed imports
#[module_export(name = "imports")]
fn imports_dll(
    ctx: &ScanContext,
    import_flags: i64,
    dll_name: RuntimeString,
) -> Option<i64> {
    imports_impl(
        ctx,
        import_flags,
        MatchCriteria::Name(dll_name.as_bstr(ctx)),
        MatchCriteria::Any,
    )
}

/// Returns true if the PE imports `func_name` from `dll_name`.
///
/// Both `func_name` and `dll_name` are case-insensitive. See [`imports_dll`]
/// for details about the `import_flags` argument.
#[module_export(name = "imports")]
fn imports_func(
    ctx: &ScanContext,
    import_flags: i64,
    dll_name: RuntimeString,
    func_name: RuntimeString,
) -> Option<bool> {
    Some(
        imports_impl(
            ctx,
            import_flags,
            MatchCriteria::Name(dll_name.as_bstr(ctx)),
            MatchCriteria::Name(func_name.as_bstr(ctx)),
        )? > 0,
    )
}

/// Returns true if the PE imports `ordinal` from `dll_name`.
///
/// `dll_name` is case-insensitive. See [`imports_dll`] for details about
/// the `import_flags` argument.
#[module_export(name = "imports")]
fn imports_ordinal(
    ctx: &ScanContext,
    import_flags: i64,
    dll_name: RuntimeString,
    ordinal: i64,
) -> Option<bool> {
    Some(
        imports_impl(
            ctx,
            import_flags,
            MatchCriteria::Name(dll_name.as_bstr(ctx)),
            MatchCriteria::Ordinal(ordinal),
        )? > 0,
    )
}

/// Returns the number of imported functions where the function's name matches
/// `func_name` and the DLL name matches `dll_name`.
///
/// Both `dll_name` and `func_name` are case-sensitive unless you use the "/i"
/// modifier in the regexp, as shown in the example below. See [`imports_dll`]
/// for details about the `import_flags` argument.
#[module_export(name = "imports")]
fn imports_regexp(
    ctx: &ScanContext,
    import_flags: i64,
    dll_name: RegexpId,
    func_name: RegexpId,
) -> Option<i64> {
    imports_impl(
        ctx,
        import_flags,
        MatchCriteria::Regexp(dll_name),
        MatchCriteria::Regexp(func_name),
    )
}

/// Returns the RVA of an import where the DLL name matches
/// `dll_name` and the function name matches `func_name`.
///
/// Both `dll_name` and `func_name` are case-insensitive.
#[module_export(name = "import_rva")]
fn import_rva_func(
    ctx: &ScanContext,
    dll_name: RuntimeString,
    func_name: RuntimeString,
) -> Option<i64> {
    let pe = ctx.module_output::<PE>()?;
    import_rva_impl(
        pe.import_details.as_slice(),
        MatchCriteria::Name(dll_name.as_bstr(ctx)),
        MatchCriteria::Name(func_name.as_bstr(ctx)),
    )
}

/// Returns the RVA of an import where the DLL name matches
/// `dll_name` and the ordinal number is `ordinal`.
///
/// `dll_name` is case-insensitive.
#[module_export(name = "import_rva")]
fn import_rva_ordinal(
    ctx: &ScanContext,
    dll_name: RuntimeString,
    ordinal: i64,
) -> Option<i64> {
    let pe = ctx.module_output::<PE>()?;
    import_rva_impl(
        pe.import_details.as_slice(),
        MatchCriteria::Name(dll_name.as_bstr(ctx)),
        MatchCriteria::Ordinal(ordinal),
    )
}

/// Returns the RVA of a delayed import where the DLL name matches
/// `dll_name` and the function name matches `func_name`.
///
/// Both `dll_name` and `func_name` are case-insensitive.
#[module_export(name = "delayed_import_rva")]
fn delayed_import_rva_func(
    ctx: &ScanContext,
    dll_name: RuntimeString,
    func_name: RuntimeString,
) -> Option<i64> {
    let pe = ctx.module_output::<PE>()?;
    import_rva_impl(
        pe.delayed_import_details.as_slice(),
        MatchCriteria::Name(dll_name.as_bstr(ctx)),
        MatchCriteria::Name(func_name.as_bstr(ctx)),
    )
}

/// Returns the RVA of an import where the DLL name matches
/// `dll_name` and the ordinal number is `ordinal`.
///
/// `dll_name` is case-insensitive.
#[module_export(name = "delayed_import_rva")]
fn delayed_import_rva_ordinal(
    ctx: &ScanContext,
    dll_name: RuntimeString,
    ordinal: i64,
) -> Option<i64> {
    let pe = ctx.module_output::<PE>()?;
    import_rva_impl(
        pe.delayed_import_details.as_slice(),
        MatchCriteria::Name(dll_name.as_bstr(ctx)),
        MatchCriteria::Ordinal(ordinal),
    )
}

/// Returns true if the PE file exports a function with the given name.
#[module_export(name = "exports")]
fn exports_func(ctx: &ScanContext, func_name: RuntimeString) -> Option<bool> {
    let (found, _) =
        exports_impl(ctx, MatchCriteria::Name(func_name.as_bstr(ctx)))?;
    Some(found)
}

/// Returns true if the PE file exports a function with the given ordinal.
#[module_export(name = "exports")]
fn exports_ordinal(ctx: &ScanContext, ordinal: i64) -> Option<bool> {
    let (found, _) = exports_impl(ctx, MatchCriteria::Ordinal(ordinal))?;
    Some(found)
}

/// Returns true if the PE file exports a function with a name that matches
/// the given regular expression.
#[module_export(name = "exports")]
fn exports_regexp(ctx: &ScanContext, func_name: RegexpId) -> Option<bool> {
    let (found, _) = exports_impl(ctx, MatchCriteria::Regexp(func_name))?;
    Some(found)
}

/// Returns true if the PE file exports a function with the given name.
#[module_export(name = "exports_index")]
fn exports_index_func(
    ctx: &ScanContext,
    func_name: RuntimeString,
) -> Option<i64> {
    match exports_impl(ctx, MatchCriteria::Name(func_name.as_bstr(ctx))) {
        Some((true, position)) => Some(position as i64),
        _ => None,
    }
}

/// Returns true if the PE file exports a function with the given ordinal.
#[module_export(name = "exports_index")]
fn exports_index_ordinal(ctx: &ScanContext, ordinal: i64) -> Option<i64> {
    match exports_impl(ctx, MatchCriteria::Ordinal(ordinal)) {
        Some((true, position)) => Some(position as i64),
        _ => None,
    }
}

/// Returns true if the PE file exports a function with a name that matches
/// the given regular expression.
#[module_export(name = "exports_index")]
fn exports_index_regexp(
    ctx: &ScanContext,
    func_name: RegexpId,
) -> Option<i64> {
    match exports_impl(ctx, MatchCriteria::Regexp(func_name)) {
        Some((true, position)) => Some(position as i64),
        _ => None,
    }
}

/// Returns true if the PE contains some resource with the specified locale
/// identifier.
///
/// Locale identifiers are 16-bit integers and can be found here:
/// https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows?view=windows-11
#[module_export]
fn locale(ctx: &ScanContext, loc: i64) -> Option<bool> {
    let pe = ctx.module_output::<PE>()?;
    let loc: u32 = match loc.try_into() {
        Ok(lang) => lang,
        Err(_) => return Some(false),
    };
    Some(pe.resources.iter().any(|resource| {
        resource.language.is_some_and(|rsrc_lang| rsrc_lang & 0xffff == loc)
    }))
}

/// Returns true if the PE contains some resource with the specified language
/// identifier.
///
/// Language identifiers are the lowest 8-bit of locale identifiers and can
/// be found here:
/// https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows?view=windows-11
#[module_export]
fn language(ctx: &ScanContext, lang: i64) -> Option<bool> {
    let pe = ctx.module_output::<PE>()?;
    let lang: u32 = match lang.try_into() {
        Ok(lang) => lang,
        Err(_) => return Some(false),
    };
    Some(pe.resources.iter().any(|resource| {
        resource.language.is_some_and(|rsrc_lang| rsrc_lang & 0xff == lang)
    }))
}

/// Returns true if the signature was valid on the date indicated by `timestamp`.
#[module_export(method_of = "pe.Signature")]
fn valid_on(
    _ctx: &ScanContext,
    signature: Rc<Struct>,
    timestamp: i64,
) -> Option<bool> {
    let not_before = signature
        .field_by_name("not_before")
        .unwrap()
        .type_value
        .try_as_integer()?;

    let not_after = signature
        .field_by_name("not_after")
        .unwrap()
        .type_value
        .try_as_integer()?;

    Some(timestamp >= not_before && timestamp <= not_after)
}

enum MatchCriteria<'a> {
    Any,
    Regexp(RegexpId),
    Name(&'a BStr),
    Ordinal(i64),
}

fn imports_impl(
    ctx: &ScanContext,
    import_flags: i64,
    expected_dll_name: MatchCriteria,
    expected_func_name: MatchCriteria,
) -> Option<i64> {
    let count_matching_funcs = |it: Iter<'_, Function>| {
        it.filter(|func| match expected_func_name {
            MatchCriteria::Any => true,
            MatchCriteria::Name(expected_name) => {
                func.name.as_ref().is_some_and(|name| {
                    expected_name.eq_ignore_ascii_case(name.as_bytes())
                })
            }
            MatchCriteria::Regexp(regexp_id) => {
                func.name.as_ref().is_some_and(|name| {
                    ctx.regexp_matches(regexp_id, name.as_bytes())
                })
            }
            MatchCriteria::Ordinal(expected_ordinal) => func
                .ordinal
                .is_some_and(|ordinal| ordinal as i64 == expected_ordinal),
        })
        .count()
    };

    let count_matching_imports = |it: Iter<'_, Import>| {
        it.filter_map(|import| {
            let name_matches = match expected_dll_name {
                MatchCriteria::Any => true,
                MatchCriteria::Name(expected_name) => {
                    import.library_name.as_ref().is_some_and(|name| {
                        expected_name.eq_ignore_ascii_case(name.as_bytes())
                    })
                }
                MatchCriteria::Regexp(regexp_id) => {
                    import.library_name.as_ref().is_some_and(|name| {
                        ctx.regexp_matches(regexp_id, name.as_bytes())
                    })
                }
                MatchCriteria::Ordinal(_) => unreachable!(),
            };
            if name_matches {
                Some(count_matching_funcs(import.functions.iter()))
            } else {
                None
            }
        })
        .sum::<usize>()
    };

    let pe = ctx.module_output::<PE>()?;
    let mut total = 0;

    if import_flags & ImportFlags::IMPORT_STANDARD as i64 != 0 {
        total += count_matching_imports(pe.import_details.iter());
    }

    if import_flags & ImportFlags::IMPORT_DELAYED as i64 != 0 {
        total += count_matching_imports(pe.delayed_import_details.iter());
    }

    total.try_into().ok()
}

fn import_rva_impl(
    imports: &[Import],
    expected_dll_name: MatchCriteria,
    expected_func_name: MatchCriteria,
) -> Option<i64> {
    for import in imports {
        let matches = match expected_dll_name {
            MatchCriteria::Any => true,
            MatchCriteria::Name(expected_name) => {
                import.library_name.as_ref().is_some_and(|name| {
                    expected_name.eq_ignore_ascii_case(name.as_bytes())
                })
            }
            MatchCriteria::Regexp(_) => unreachable!(),
            MatchCriteria::Ordinal(_) => unreachable!(),
        };

        if matches {
            for func in import.functions.iter() {
                match expected_func_name {
                    MatchCriteria::Any => return func.rva.map(|r| r as i64),
                    MatchCriteria::Name(expected_name) => {
                        if func.name.as_ref().is_some_and(|name| {
                            expected_name.eq_ignore_ascii_case(name.as_bytes())
                        }) {
                            return func.rva.map(|r| r as i64);
                        }
                    }
                    MatchCriteria::Ordinal(expected_ordinal) => {
                        if func.ordinal.is_some_and(|ordinal| {
                            ordinal as i64 == expected_ordinal
                        }) {
                            return func.rva.map(|r| r as i64);
                        }
                    }
                    MatchCriteria::Regexp(_) => unreachable!(),
                }
            }
        }
    }

    None
}

fn exports_impl(
    ctx: &ScanContext,
    expected_func_name: MatchCriteria,
) -> Option<(bool, usize)> {
    let pe = ctx.module_output::<PE>()?;
    pe.export_details
        .iter()
        .find_position(|export| match expected_func_name {
            MatchCriteria::Any => true,
            MatchCriteria::Regexp(regexp_id) => {
                export.name.as_ref().is_some_and(|name| {
                    ctx.regexp_matches(regexp_id, name.as_bytes())
                })
            }
            MatchCriteria::Name(expected_name) => {
                export.name.as_ref().is_some_and(|name| {
                    expected_name.eq_ignore_ascii_case(name.as_bytes())
                })
            }
            MatchCriteria::Ordinal(expected_ordinal) => export
                .ordinal
                .as_ref()
                .is_some_and(|ordinal| expected_ordinal == *ordinal as i64),
        })
        .map_or(Some((false, 0)), |(position, _)| Some((true, position)))
}
