/*! YARA module that parses .NET files.

This allows creating YARA rules based on .NET metadata.
 */

use crate::modules::prelude::*;
use crate::modules::protos::dotnet::*;

pub mod parser;

#[module_main]
fn main(
    data: &[u8],
    _meta: Option<&[u8]>,
) -> Result<Dotnet, ModuleError> {
    match parser::Dotnet::parse(data) {
        Ok(dotnet) => Ok(dotnet.into()),
        Err(_) => {
            let mut dotnet = Dotnet::new();
            dotnet.is_dotnet = Some(false);
            Ok(dotnet)
        }
    }
}
