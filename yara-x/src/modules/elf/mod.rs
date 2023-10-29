use crate::modules::prelude::*;
use crate::modules::protos::elf::*;

pub mod parser;

#[module_main]
fn main(ctx: &ScanContext) -> ELF {
    match parser::ElfParser::new().parse(ctx.scanned_data()) {
        Ok(elf) => elf,
        Err(_) => ELF::new(),
    }
}
