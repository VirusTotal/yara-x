/*! YARA module that parses PE files.

This allows creating YARA rules based on PE metadata, including sections,
imports and exports, resources, etc.
 */

use crate::modules::prelude::*;
use crate::modules::protos::pe::*;

#[cfg(test)]
mod tests;

pub mod parser;

#[module_main]
fn main(ctx: &ScanContext) -> PE {
    match parser::PEParser::new().parse(ctx.scanned_data()) {
        Ok(pe) => pe,
        Err(_) => {
            let mut pe = PE::new();
            pe.is_pe = Some(false);
            pe
        }
    }
}

#[module_export(name = "rich_signature.toolid")]
fn rich_toolid(ctx: &mut ScanContext, toolid: i64) -> Option<i64> {
    _rich_version(ctx.module_output::<PE>()?, Some(toolid), None)
}

#[module_export(name = "rich_signature.version")]
fn rich_version(ctx: &mut ScanContext, version: i64) -> Option<i64> {
    _rich_version(ctx.module_output::<PE>()?, None, Some(version))
}

#[module_export(name = "rich_signature.version")]
fn rich_version_toolid(
    ctx: &mut ScanContext,
    version: i64,
    toolid: i64,
) -> Option<i64> {
    _rich_version(ctx.module_output::<PE>()?, Some(toolid), Some(version))
}

#[module_export(name = "rich_signature.toolid")]
fn rich_toolid_version(
    ctx: &mut ScanContext,
    toolid: i64,
    version: i64,
) -> Option<i64> {
    _rich_version(ctx.module_output::<PE>()?, Some(toolid), Some(version))
}

fn _rich_version(
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
