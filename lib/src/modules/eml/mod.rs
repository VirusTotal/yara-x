/*! YARA module that parses EML files.

An EML file is the standard file format for email, according to RFC 2045 [1]

[1]: https://datatracker.ietf.org/doc/html/rfc2045
 */

use crate::mods::prelude::*;
use crate::modules::protos::eml::*;
mod address;
pub mod parser;
mod rfc2047;

#[cfg(test)]
mod tests;

fn main(_ctx: &mut ModuleContext, data: &[u8]) -> Result<Eml, ModuleError> {
    match parser::EmlParser::new().parse(data) {
        Ok(eml) => Ok(eml),
        Err(_) => {
            let mut eml = Eml::new();
            eml.is_eml = Some(false);
            Ok(eml)
        }
    }
}

/// Returns true if the top-level headers contain a header named `header`.
///
/// `header` is case-insensitive.
#[module_export]
fn has_header(
    ctx: &ScanContext,
    header: RuntimeString,
) -> Option<bool> {
    let eml = ctx.module_output::<Eml>()?;
    let header = header.as_bstr(ctx);
    let headers = &eml.headers;

    let found = headers.iter().any(|h| h.key().eq_ignore_ascii_case(header));

    Some(found)
}

/// Returns the value of the first top-level header named `name`, or
/// undefined if there is none.
///
/// `name` is case-insensitive.
#[module_export]
fn header(ctx: &ScanContext, name: RuntimeString) -> Option<RuntimeString> {
    let eml = ctx.module_output::<Eml>()?;
    let name = name.as_bstr(ctx);
    let header = eml.headers.iter().find(|h| h.key().eq_ignore_ascii_case(name))?;

    Some(RuntimeString::new(header.value().to_vec()))
}

/// Returns how many top-level headers are named `name`.
///
/// `name` is case-insensitive.
#[module_export]
fn header_count(ctx: &ScanContext, name: RuntimeString) -> Option<i64> {
    let eml = ctx.module_output::<Eml>()?;
    let name = name.as_bstr(ctx);
    let count =
        eml.headers.iter().filter(|h| h.key().eq_ignore_ascii_case(name)).count();

    Some(count as i64)
}

register_module!("eml", Eml, main);
