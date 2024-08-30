/*! YARA module that parses .NET files.

This allows creating YARA rules based on .NET metadata.
 */

use crate::modules::prelude::*;
use crate::modules::protos::dotnet::*;
use crate::ScanInputRaw;

pub mod parser;

#[module_main]
fn main(input: &ScanInputRaw) -> Dotnet {
    match parser::Dotnet::parse(input.target) {
        Ok(dotnet) => dotnet.into(),
        Err(_) => {
            let mut dotnet = Dotnet::new();
            dotnet.is_dotnet = Some(false);
            dotnet
        }
    }
}
