use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

use byteorder::{BigEndian, ByteOrder};
use nom::{number::complete::*, IResult};

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

// Get magic constant from macho file
fn parse_magic(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
}

// Parse Mach-O header
fn parse_macho_header(input: &[u8]) -> IResult<&[u8], MachOHeader64> {
    let (input, magic) = parse_magic(input)?;
    let (input, cputype) = le_u32(input)?;
    let (input, cpusubtype) = le_u32(input)?;
    let (input, filetype) = le_u32(input)?;
    let (input, ncmds) = le_u32(input)?;
    let (input, sizeofcmds) = le_u32(input)?;
    let (input, flags) = le_u32(input)?;

    // Determine if we should parse the reserved field based on the magic value
    let (input, reserved) =
        if !is_32_bit(magic) { le_u32(input)? } else { (input, 0) };

    Ok((
        input,
        MachOHeader64 {
            magic,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            flags,
            reserved,
        },
    ))
}

// Check if given file is basic Mach-O file
fn is_macho_file_block(data: &[u8]) -> bool {
    match parse_magic(data) {
        Ok((_, magic)) => {
            matches!(magic, MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64)
        }
        _ => false,
    }
}

// Check if given file is FAT Mach-O file
fn is_fat_macho_file_block(data: &[u8]) -> bool {
    match parse_magic(data) {
        Ok((_, magic)) => matches!(
            magic,
            FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64
        ),
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

    if let Ok((_, mut header)) = parse_macho_header(data) {
        // Byte conversion (swap) if necessary
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
        if !is_32_bit(header.magic) {
            macho_proto.set_reserved(header.reserved);
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
        println!("CPU Type: {}", header.cputype);
        println!("CPU Subtype: {}", header.cpusubtype);
        println!("File Type: {}", header.filetype);
        println!("Number of Commands: {}", header.ncmds);
        println!("Size of Commands: {}", header.sizeofcmds);
        println!("Flags: 0x{:x}", header.flags);
        println!("Reserved: 0x{:x}", header.reserved);
    }
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
