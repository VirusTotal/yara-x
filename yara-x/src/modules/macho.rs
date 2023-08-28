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

// Define command type constants
const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;

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

// Load Command struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

// Get magic constant from macho file
fn parse_magic(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
}

// Handle the LC_SEGMENT command
fn handle_segment_command(
    command_data: &[u8],
    size: usize,
    seg_count: &mut u64,
    macho_proto: &mut Macho,
) {
    // TODO: Implement the logic for handling the LC_SEGMENT command
    *seg_count += 1;
}

// Handle the LC_SEGMENT_64 command
fn handle_segment_64_command(
    command_data: &[u8],
    size: usize,
    seg_count: &mut u64,
    macho_proto: &mut Macho,
) {
    // TODO: Implement the logic for handling the LC_SEGMENT_64 command
    *seg_count += 1;
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
    header.cputype = BigEndian::read_u32(&header.cputype.to_le_bytes());
    header.cpusubtype = BigEndian::read_u32(&header.cpusubtype.to_le_bytes());
    header.filetype = BigEndian::read_u32(&header.filetype.to_le_bytes());
    header.ncmds = BigEndian::read_u32(&header.ncmds.to_le_bytes());
    header.sizeofcmds = BigEndian::read_u32(&header.sizeofcmds.to_le_bytes());
    header.flags = BigEndian::read_u32(&header.flags.to_le_bytes());

    // Only swap the reserved field for 64-bit files
    if !is_32_bit(header.magic) {
        header.reserved = BigEndian::read_u32(&header.reserved.to_le_bytes());
    }
}

// Swap Mach-O load command from BigEndian to LittleEndian
fn swap_load_command(command: &mut LoadCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
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

// Parse LoadCommand
fn parse_load_command(input: &[u8]) -> IResult<&[u8], LoadCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;

    Ok((input, LoadCommand { cmd, cmdsize }))
}

// Parse Mach-O commands
fn parse_macho_commands(
    data: &[u8],
    header: &MachOHeader64,
    macho_proto: &mut Macho,
) -> u64 {
    // Commands are located after the header so we need to add header size to offset
    let mut command_offset = if is_32_bit(header.magic) {
        std::mem::size_of::<MachOHeader32>()
    } else {
        std::mem::size_of::<MachOHeader64>()
    };

    let mut seg_count = 0;

    // Loop over load commands and parse them
    for _ in 0..header.ncmds {
        if let Ok((remaining_data, mut command)) =
            parse_load_command(&data[command_offset..])
        {
            // Swap load command bytes similary as was done for header
            if should_swap_bytes(header.magic) {
                swap_load_command(&mut command);
            }

            // For now only LC_SEGMENT and LC_SEGMENT_64 commands are supported
            match command.cmd {
                LC_SEGMENT => {
                    handle_segment_command(
                        remaining_data,
                        command.cmdsize as usize,
                        &mut seg_count,
                        macho_proto,
                    );
                }
                LC_SEGMENT_64 => {
                    handle_segment_64_command(
                        remaining_data,
                        command.cmdsize as usize,
                        &mut seg_count,
                        macho_proto,
                    );
                }
                _ => {}
            }

            // Add command size to offset in order to process next command
            command_offset += command.cmdsize as usize;
        } else {
            // If parsing fails, break out of the loop
            break;
        }
    }

    seg_count
}

// Parse basic Mach-O file
fn parse_macho_file(data: &[u8], macho_proto: &mut Macho) {
    // File is too small to contain Mach-O header
    if data.len() < std::mem::size_of::<MachOHeader64>() {
        return;
    }

    // Declare the header variable with an Option type to be able to use it later
    let mut header: Option<MachOHeader64> = None;

    if let Ok((_, mut parsed_header)) = parse_macho_header(data) {
        // Byte conversion (swap) if necessary
        if should_swap_bytes(parsed_header.magic) {
            swap_mach_header(&mut parsed_header);
        }

        // Set protobuf values for Mach-O header
        macho_proto.set_magic(parsed_header.magic);
        macho_proto.set_cputype(parsed_header.cputype);
        macho_proto.set_cpusubtype(parsed_header.cpusubtype);
        macho_proto.set_filetype(parsed_header.filetype);
        macho_proto.set_ncmds(parsed_header.ncmds);
        macho_proto.set_sizeofcmds(parsed_header.sizeofcmds);
        macho_proto.set_flags(parsed_header.flags);

        // Only set the reserved field in the protobuf for 64-bit files
        if !is_32_bit(parsed_header.magic) {
            macho_proto.set_reserved(parsed_header.reserved);
        }

        // Print header fields in hexadecimal format
        println!("Magic: 0x{:x}", parsed_header.magic);
        println!("CPU Type: {}", parsed_header.cputype);
        println!("CPU Subtype: {}", parsed_header.cpusubtype);
        println!("File Type: {}", parsed_header.filetype);
        println!("Number of Commands: {}", parsed_header.ncmds);
        println!("Size of Commands: {}", parsed_header.sizeofcmds);
        println!("Flags: 0x{:x}", parsed_header.flags);
        println!("Reserved: 0x{:x}", parsed_header.reserved);

        // Assign the parsed header to the header_option variable
        header = Some(parsed_header);
    }

    // Check if the header has a value and then parse the commands
    if let Some(header) = header {
        let seg_count = parse_macho_commands(data, &header, macho_proto);
        macho_proto.set_number_of_segments(seg_count);

        println!("Number of segments: {}", seg_count);
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

    // parse basic macho file
    if is_macho_file_block(data) {
        parse_macho_file(data, &mut macho_proto);
    }

    if is_fat_macho_file_block(data) {
        //parse_fat_macho_file(data, &mut macho_proto);
    }

    macho_proto
}
