/*! Modules that parses LNK files.

A LNK file is a Windows Shortcut that serves as a pointer to open a file,
folder, or application. This module specializes in parsing LNK files and
extracting valuable metadata, facilitating the creation of YARA rules based
on this metadata.

This module is based on the [`LNK file format specification`][1] published
by Microsoft, the a [`non-official specification by Joachim Metz`][2].

[1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
[2]: https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc
 */

use crate::modules::prelude::*;
use crate::modules::protos::lnk::*;

mod parser;

#[cfg(test)]
mod tests;

#[module_main]
fn main(ctx: &ScanContext) -> Lnk {
    match parser::LnkParser::new().parse(ctx.scanned_data()) {
        Ok(lnk) => lnk,
        Err(_) => {
            let mut lnk = Lnk::new();
            lnk.is_lnk = Some(false);
            lnk
        }
    }
}