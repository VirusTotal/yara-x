//! Module that handles parsing of Mach-O files from ScanContext bytes
//! The implementation provides utility functions to determine
//! if a given binary data corresponds to a Mach-O file, and further
//! breaks down the data into relevant Mach-O structures and populates
//! both protobuf structure fields and constants. This together with
//! also exported functions can be later used in YARA rules.

use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

mod parser;
#[cfg(test)]
mod tests;

/// Get the index of a Mach-O file within a fat binary based on CPU type.
///
/// This function iterates through the architecture types contained in a
/// Mach-O fat binary and returns the index of the file that matches the
/// specified CPU type.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type to search for within the fat binary.
///
/// # Returns
///
/// An `Option<i64>` containing the index of the matching Mach-O file, or
/// `None` if no match is found.
#[module_export(name = "file_index_for_arch")]
fn file_index_type(ctx: &mut ScanContext, type_arg: i64) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let Some(cputype) = arch.cputype {
                if cputype as i64 == type_arg {
                    return Some(i as i64);
                }
            }
        }
    }

    None
}

/// Get the index of a Mach-O file within a fat binary based on both
/// CPU type and subtype.
///
/// This function extends `file_index_type` by also considering the CPU subtype
/// during the search, allowing for more precise matching.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type to search for.
/// * `subtype_arg`: The CPU subtype to search for.
///
/// # Returns
///
/// An `Option<i64>` containing the index of the matching Mach-O file, or
/// `None` if no match is found.
#[module_export(name = "file_index_for_arch")]
fn file_index_subtype(
    ctx: &mut ScanContext,
    type_arg: i64,
    subtype_arg: i64,
) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let (Some(cputype), Some(cpusubtype)) =
                (arch.cputype, arch.cpusubtype)
            {
                if cputype as i64 == type_arg
                    && cpusubtype as i64 == subtype_arg
                {
                    return Some(i as i64);
                }
            }
        }
    }

    None
}

/// Get the real entry point offset for a specific CPU type within a fat
/// Mach-O binary.
///
/// It navigates through the architectures in the binary, finds the one that
/// matches the specified CPU type, and returns its entry point offset.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type of the desired architecture.
///
/// # Returns
///
/// An `Option<i64>` containing the offset of the entry point for the specified
/// architecture, or `None` if not found.
#[module_export(name = "entry_point_for_arch")]
fn ep_for_arch_type(ctx: &mut ScanContext, type_arg: i64) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let Some(cputype) = arch.cputype {
                if cputype as i64 == type_arg {
                    let file_offset = arch.offset?;
                    let entry_point = macho.file.get(i)?.entry_point?;
                    return file_offset
                        .checked_add(entry_point)
                        .map(|sum| sum as i64);
                }
            }
        }
    }

    None
}

/// Get the real entry point offset for a specific CPU type and subtype
/// within a fat Mach-O binary.
///
/// Similar to `ep_for_arch_type`, but adds consideration for the CPU subtype
/// to allow for more precise location of the entry point.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type of the desired architecture.
/// * `subtype_arg`: The CPU subtype of the desired architecture.
///
/// # Returns
///
/// An `Option<i64>` containing the offset of the entry point for the specified
/// architecture and subtype, or `None` if not found.
#[module_export(name = "entry_point_for_arch")]
fn ep_for_arch_subtype(
    ctx: &mut ScanContext,
    type_arg: i64,
    subtype_arg: i64,
) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let (Some(cputype), Some(cpusubtype)) =
                (arch.cputype, arch.cpusubtype)
            {
                if cputype as i64 == type_arg
                    && cpusubtype as i64 == subtype_arg
                {
                    let file_offset = arch.offset?;
                    let entry_point = macho.file.get(i)?.entry_point?;
                    return file_offset
                        .checked_add(entry_point)
                        .map(|sum| sum as i64);
                }
            }
        }
    }

    None
}

/// Returns true if the Mach-O parsed entitlements contain `entitlement`
///
/// `entitlement` is case-insensitive.
#[module_export]
fn has_entitlement(
    ctx: &ScanContext,
    entitlement: RuntimeString,
) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected = entitlement.as_bstr(ctx);

    for entitlement in macho.entitlements.iter() {
        if expected.eq_ignore_ascii_case(entitlement.as_bytes()) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for entitlement in file.entitlements.iter() {
            if expected.eq_ignore_ascii_case(entitlement.as_bytes()) {
                return Some(true);
            }
        }
    }

    Some(false)
}

/// Returns true if the Mach-O parsed dylibs contain `dylib_name`
///
/// `dylib_name` is case-insensitive.
#[module_export]
fn has_dylib(ctx: &ScanContext, dylib_name: RuntimeString) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected_name = dylib_name.as_bstr(ctx);

    for dylib in macho.dylibs.iter() {
        if dylib.name.as_ref().is_some_and(|name| {
            expected_name.eq_ignore_ascii_case(name.as_bytes())
        }) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for dylib in file.dylibs.iter() {
            if dylib.name.as_ref().is_some_and(|name| {
                expected_name.eq_ignore_ascii_case(name.as_bytes())
            }) {
                return Some(true);
            }
        }
    }

    Some(false)
}

/// Returns true if the Mach-O parsed rpaths contain `rpath`
///
/// `rpath` is case-insensitive.
#[module_export]
fn has_rpath(ctx: &ScanContext, rpath: RuntimeString) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected_rpath = rpath.as_bstr(ctx);

    for rp in macho.rpaths.iter() {
        if expected_rpath.eq_ignore_ascii_case(rp.as_bytes()) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for rp in file.rpaths.iter() {
            if expected_rpath.eq_ignore_ascii_case(rp.as_bytes()) {
                return Some(true);
            }
        }
    }

    Some(false)
}

#[module_main]
fn main(input: &[u8]) -> Macho {
    match parser::MachO::parse(input) {
        Ok(macho) => macho.into(),
        Err(_) => Macho::new(),
    }
}
