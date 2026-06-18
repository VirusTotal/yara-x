/*! YARA module that parses .NET files.

This allows creating YARA rules based on .NET metadata.
 */
use crate::mods::prelude::*;
use crate::modules::protos::dotnet::*;

pub mod parser;

fn main(_ctx: &ScanContext, data: &[u8], _meta: Option<&[u8]>) -> Result<Dotnet, ModuleError> {
    match parser::Dotnet::parse(data) {
        Ok(dotnet) => Ok(dotnet.into()),
        Err(_) => {
            let mut dotnet = Dotnet::new();
            dotnet.is_dotnet = Some(false);
            Ok(dotnet)
        }
    }
}

register_module!("dotnet", Dotnet, main);
