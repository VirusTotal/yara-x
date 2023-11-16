/*! YARA module that parses PE files.

This allows creating YARA rules based on PE metadata, including sections,
imports and exports, resources, etc.
 */

use std::slice::Iter;

use bstr::BStr;

use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::pe::*;

#[cfg(test)]
mod tests;

pub mod parser;

#[module_main]
fn main(input: &[u8]) -> PE {
    match parser::PE::parse(input) {
        Ok(pe) => pe.into(),
        Err(_) => {
            let mut pe = PE::new();
            pe.is_pe = Some(false);
            pe
        }
    }
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
    ctx: &mut ScanContext,
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
    ctx: &mut ScanContext,
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
    ctx: &mut ScanContext,
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
/// Both `dll_name` and `func_name` are case sensitive unless you use the "/i"
/// modifier in the regexp, as shown in the example below.
#[module_export(name = "imports")]
fn standard_imports_regexp(
    ctx: &mut ScanContext,
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
    ctx: &mut ScanContext,
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
    ctx: &mut ScanContext,
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
    ctx: &mut ScanContext,
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
/// Both `dll_name` and `func_name` are case sensitive unless you use the "/i"
/// modifier in the regexp, as shown in the example below. See [`imports_dll`]
/// for details about the `import_flags` argument.
#[module_export(name = "imports")]
fn imports_regexp(
    ctx: &mut ScanContext,
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
