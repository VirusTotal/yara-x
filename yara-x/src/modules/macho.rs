use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

use byteorder::{BigEndian, ByteOrder};
use std::convert::TryInto;

// Define Mach-O header constats
// May be moved away later
const MH_MAGIC: u32 = 0xFEEDFACE;
const MH_CIGAM: u32 = 0xCEFAEDFE;
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_CIGAM: u32 = 0xBEBAFECA;
const FAT_MAGIC_64: u32 = 0xCAFEBABF;
const FAT_CIGAM_64: u32 = 0xBFBAFECA;

// 32bit Mach-O header struct
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

// 64bit Mach-O header struct
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

// Check if given file is basic Mach-O file
fn is_macho_file_block(data: &[u8]) -> bool {
    let magic = u32::from_ne_bytes(data[0..4].try_into().unwrap());
    match magic {
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 => true,
        _ => false,
    }
}

// Check if given file is FAT Mach-O file
fn is_fat_macho_file_block(data: &[u8]) -> bool {
    let magic = u32::from_ne_bytes(data[0..4].try_into().unwrap());
    match magic {
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => true,
        _ => false,
    }
}

// Check if given file is 32bit Mach-O file
fn is_32_bit(magic: u32) -> bool {
    let bytes = magic.to_ne_bytes();
    bytes[0] == 0xce || bytes[3] == 0xce
}

// If given file is BigEndian we want to swap bytes to LittleEndian
// If file is already in LittleEndian format return false
fn should_swap_bytes(magic: u32) -> bool {
    match magic {
        MH_CIGAM | MH_CIGAM_64 | FAT_CIGAM | FAT_CIGAM_64 => true,
        _ => false,
    }
}

// Swap Mach-O headers from BigEndian to LittleEndian
fn swap_mach_header(header: &mut MachOHeader64) {
    if should_swap_bytes(header.magic) {
        header.cputype = BigEndian::read_u32(&header.cputype.to_le_bytes());
        header.cpusubtype =
            BigEndian::read_u32(&header.cpusubtype.to_le_bytes());
        header.filetype = BigEndian::read_u32(&header.filetype.to_le_bytes());
        header.ncmds = BigEndian::read_u32(&header.ncmds.to_le_bytes());
        header.sizeofcmds =
            BigEndian::read_u32(&header.sizeofcmds.to_le_bytes());
        header.flags = BigEndian::read_u32(&header.flags.to_le_bytes());

        // Only swap the reserved field for 64-bit files
        if !is_32_bit(header.magic) {
            header.reserved =
                BigEndian::read_u32(&header.reserved.to_le_bytes());
        }
    }
}

// Parse basic Mach-O file
fn parse_macho_file(data: &[u8], macho_proto: &mut Macho) {
    // File is too small to contain Mach-O header
    if data.len() < std::mem::size_of::<MachOHeader64>() {
        return;
    }

    // Get header size by determining if file is 32 or 64 bit
    let header_size =
        if is_32_bit(u32::from_ne_bytes(data[0..4].try_into().unwrap())) {
            std::mem::size_of::<MachOHeader32>()
        } else {
            std::mem::size_of::<MachOHeader64>()
        };

    // Populate Mach-O header struct
    let mut header: MachOHeader64 = MachOHeader64 {
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

    if should_swap_bytes(header.magic) {
        swap_mach_header(&mut header);
    }

    // Set protobuf values for Mach-O header
    macho_proto.set_magic(header.magic);
    macho_proto.set_cputype(header.cputype);
    macho_proto.set_cpusubtype(header.cpusubtype);
    macho_proto.set_filetype(header.filetype);
    macho_proto.set_ncmds(header.ncmds);
    macho_proto.set_sizeofcmds(header.sizeofcmds);
    macho_proto.set_flags(header.flags);

    // Only set the reserved field in the protobuf for 64-bit files
    if !is_32_bit(header.magic) {
        macho_proto.set_reserved(header.reserved);
    }

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
    let mut macho_proto = Macho::new();

    // Get a &[u8] slice with the content of the file being scanned.
    let data = ctx.scanned_data();

    // If data is too short to be valid Mach-O file, return empty protobuf
    if data.len() < 4 {
        println!("Data is too short to be a valid Mach-O file.");
        return macho_proto;
    }

    if is_macho_file_block(data) {
        parse_macho_file(data, &mut macho_proto);
    }

    if is_fat_macho_file_block(data) {
        //parse_fat_macho_file(data, &mut macho_proto);
    }

    macho_proto
}
