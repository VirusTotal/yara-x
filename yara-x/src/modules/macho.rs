use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

use std::convert::TryInto;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct MachOHeader32 {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct MachOHeader64 {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

fn is_32_bit(magic: u32) -> bool {
    let bytes = magic.to_ne_bytes();
    bytes[0] == 0xce || bytes[3] == 0xce
}

fn parse_macho_header(data: &[u8]) {
    if data.len() < std::mem::size_of::<MachOHeader64>() {
        return;
    }

    let header_size =
        if is_32_bit(u32::from_ne_bytes(data[0..4].try_into().unwrap())) {
            std::mem::size_of::<MachOHeader32>()
        } else {
            std::mem::size_of::<MachOHeader64>()
        };

    let header: MachOHeader64 = MachOHeader64 {
        magic: u32::from_ne_bytes(data[0..4].try_into().unwrap()),
        cputype: u32::from_ne_bytes(data[4..8].try_into().unwrap()),
        cpusubtype: u32::from_ne_bytes(data[8..12].try_into().unwrap()),
        filetype: u32::from_ne_bytes(data[12..16].try_into().unwrap()),
        ncmds: u32::from_ne_bytes(data[16..20].try_into().unwrap()),
        sizeofcmds: u32::from_ne_bytes(data[20..24].try_into().unwrap()),
        flags: u32::from_ne_bytes(data[24..28].try_into().unwrap()),
        reserved: if header_size == std::mem::size_of::<MachOHeader32>() {
            0 // Default value for 32-bit Mach-O
        } else {
            u32::from_ne_bytes(data[28..32].try_into().unwrap())
        },
    };
    // Print header fields in hexadecimal format
    println!("Magic: 0x{:x}", header.magic);
    println!("CPU Type: 0x{:x}", header.cputype);
    println!("CPU Subtype: 0x{:x}", header.cpusubtype);
    println!("File Type: 0x{:x}", header.filetype);
    println!("Number of Commands: 0x{:x}", header.ncmds);
    println!("Size of Commands: 0x{:x}", header.sizeofcmds);
    println!("Flags: 0x{:x}", header.flags);
    println!("Reserved: 0x{:x}", header.reserved);
}

#[module_main]
fn main(ctx: &ScanContext) -> Macho {
    // Create an empty instance of the Macho protobuf
    let macho_proto = Macho::new();

    // Get a &[u8] slice with the content of the file being scanned.
    let data = ctx.scanned_data();

    // Parse the MachO header
    parse_macho_header(data);

    macho_proto
}
