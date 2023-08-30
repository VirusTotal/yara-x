use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};
use nom::{bytes::complete::take, number::complete::*, IResult};

// Mach-O file needs to have at least header of size 28 to be considered correct
// Real minimum size of Mach-O file would be higher
const VALID_MACHO_LENGTH: usize = 28;

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

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct SegmentCommand32 {
    cmd: u32,
    cmdsize: u32,
    segname: [u8; 16],
    vmaddr: u32,
    vmsize: u32,
    fileoff: u32,
    filesize: u32,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct SegmentCommand64 {
    cmd: u32,
    cmdsize: u32,
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct Section32 {
    sectname: [u8; 16],
    segname: [u8; 16],
    addr: u32,
    size: u32,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct Section64 {
    sectname: [u8; 16],
    segname: [u8; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

// Get magic constant from Mach-O file
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
    // Check if segment size is not less than SegmentCommand32 struct size
    if size < std::mem::size_of::<SegmentCommand32>() {
        return;
    }

    // Parse segment command data
    if let Ok((remaining_data, mut sg)) = parse_segment_command(command_data) {
        if let Some(magic_value) = macho_proto.magic {
            if should_swap_bytes(magic_value) {
                swap_segment_command(&mut sg);
            }
        }

        // Print the sg structure in the specified format
        println!("Segment Commands:");
        println!("Command: 0x{:x}", sg.cmd);
        println!("Command Size: {}", sg.cmdsize);
        println!(
            "Segment Name: {}",
            std::str::from_utf8(&sg.segname).unwrap_or_default()
        );
        println!("VM Address: 0x{:x}", sg.vmaddr);
        println!("VM Size: 0x{:x}", sg.vmsize);
        println!("File Offset: {}", sg.fileoff);
        println!("File Size: {}", sg.filesize);
        println!("Max Protection: 0x{:x}", sg.maxprot);
        println!("Init Protection: 0x{:x}", sg.initprot);
        println!("Number of Sections: {}", sg.nsects);
        println!("Flags: 0x{:x}", sg.flags);

        // TODO: Set the segment fields in the macho_proto
        let mut sections_data = remaining_data;
        for _ in 0..sg.nsects {
            if let Ok((remaining_sections, sec)) = parse_section(sections_data)
            {
                // TODO: Set the section fields in the macho_proto
                sections_data = remaining_sections;
            } else {
                break;
            }
        }

        *seg_count += 1;
    }
}

// Handle the LC_SEGMENT_64 command
fn handle_segment_command_64(
    command_data: &[u8],
    size: usize,
    seg_count: &mut u64,
    macho_proto: &mut Macho,
) {
    // Check if segment size is not less than SegmentCommand64 struct size
    if size < std::mem::size_of::<SegmentCommand64>() {
        return;
    }

    // Parse segment command data
    if let Ok((remaining_data, mut sg)) =
        parse_segment_command_64(command_data)
    {
        if let Some(magic_value) = macho_proto.magic {
            if should_swap_bytes(magic_value) {
                swap_segment_command_64(&mut sg);
            }
        }

        // Print the sg structure in the specified format
        println!("Segment Commands:");
        println!("Command: 0x{:x}", sg.cmd);
        println!("Command Size: {}", sg.cmdsize);
        println!(
            "Segment Name: {}",
            std::str::from_utf8(&sg.segname).unwrap_or_default()
        );
        println!("VM Address: 0x{:x}", sg.vmaddr);
        println!("VM Size: 0x{:x}", sg.vmsize);
        println!("File Offset: {}", sg.fileoff);
        println!("File Size: {}", sg.filesize);
        println!("Max Protection: 0x{:x}", sg.maxprot);
        println!("Init Protection: 0x{:x}", sg.initprot);
        println!("Number of Sections: {}", sg.nsects);
        println!("Flags: 0x{:x}", sg.flags);

        // TODO: Set the segment fields in the macho_proto
        let mut sections_data = remaining_data;
        for _ in 0..sg.nsects {
            if let Ok((remaining_sections, sec)) =
                parse_section_64(sections_data)
            {
                // TODO: Set the section fields in the macho_proto
                sections_data = remaining_sections;
            } else {
                break;
            }
        }

        *seg_count += 1;
    }
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

    // Only swap the reserved field for 64bit files
    if !is_32_bit(header.magic) {
        header.reserved = BigEndian::read_u32(&header.reserved.to_le_bytes());
    }
}

// Swap Mach-O load command from BigEndian to LittleEndian
fn swap_load_command(command: &mut LoadCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
}

// Swap Mach-O segment command for 32bit files
fn swap_segment_command(segment: &mut SegmentCommand32) {
    segment.cmd = BigEndian::read_u32(&segment.cmd.to_le_bytes());
    segment.cmdsize = BigEndian::read_u32(&segment.cmdsize.to_le_bytes());
    segment.vmaddr = BigEndian::read_u32(&segment.vmaddr.to_le_bytes());
    segment.vmsize = BigEndian::read_u32(&segment.vmsize.to_le_bytes());
    segment.fileoff = BigEndian::read_u32(&segment.fileoff.to_le_bytes());
    segment.filesize = BigEndian::read_u32(&segment.filesize.to_le_bytes());
    segment.maxprot = BigEndian::read_u32(&segment.maxprot.to_le_bytes());
    segment.initprot = BigEndian::read_u32(&segment.initprot.to_le_bytes());
    segment.nsects = BigEndian::read_u32(&segment.nsects.to_le_bytes());
    segment.flags = BigEndian::read_u32(&segment.flags.to_le_bytes());
}

// Swap Mach-O segment command for 64bit files
fn swap_segment_command_64(segment: &mut SegmentCommand64) {
    segment.cmd = BigEndian::read_u32(&segment.cmd.to_le_bytes());
    segment.cmdsize = BigEndian::read_u32(&segment.cmdsize.to_le_bytes());
    segment.vmaddr = BigEndian::read_u64(&segment.vmaddr.to_le_bytes());
    segment.vmsize = BigEndian::read_u64(&segment.vmsize.to_le_bytes());
    segment.fileoff = BigEndian::read_u64(&segment.fileoff.to_le_bytes());
    segment.filesize = BigEndian::read_u64(&segment.filesize.to_le_bytes());
    segment.maxprot = BigEndian::read_u32(&segment.maxprot.to_le_bytes());
    segment.initprot = BigEndian::read_u32(&segment.initprot.to_le_bytes());
    segment.nsects = BigEndian::read_u32(&segment.nsects.to_le_bytes());
    segment.flags = BigEndian::read_u32(&segment.flags.to_le_bytes());
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

// Parsing function for Mach-O 32bit Command segment
fn parse_segment_command(input: &[u8]) -> IResult<&[u8], SegmentCommand32> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, segname) = take(16usize)(input)?;
    let (input, vmaddr) = le_u32(input)?;
    let (input, vmsize) = le_u32(input)?;
    let (input, fileoff) = le_u32(input)?;
    let (input, filesize) = le_u32(input)?;
    let (input, maxprot) = le_u32(input)?;
    let (input, initprot) = le_u32(input)?;
    let (input, nsects) = le_u32(input)?;
    let (input, flags) = le_u32(input)?;

    Ok((
        input,
        SegmentCommand32 {
            cmd,
            cmdsize,
            segname: *array_ref![segname, 0, 16],
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
        },
    ))
}

// Parsing function for Mach-O 64bit Command segment
fn parse_segment_command_64(input: &[u8]) -> IResult<&[u8], SegmentCommand64> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, segname) = take(16usize)(input)?;
    let (input, vmaddr) = le_u64(input)?;
    let (input, vmsize) = le_u64(input)?;
    let (input, fileoff) = le_u64(input)?;
    let (input, filesize) = le_u64(input)?;
    let (input, maxprot) = le_u32(input)?;
    let (input, initprot) = le_u32(input)?;
    let (input, nsects) = le_u32(input)?;
    let (input, flags) = le_u32(input)?;

    Ok((
        input,
        SegmentCommand64 {
            cmd,
            cmdsize,
            segname: *array_ref![segname, 0, 16],
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
        },
    ))
}

// Parsing function for Mach-O 32bit Section
fn parse_section(input: &[u8]) -> IResult<&[u8], Section32> {
    let (input, sectname) = take(16usize)(input)?;
    let (input, segname) = take(16usize)(input)?;
    let (input, addr) = le_u32(input)?;
    let (input, size) = le_u32(input)?;
    let (input, offset) = le_u32(input)?;
    let (input, align) = le_u32(input)?;
    let (input, reloff) = le_u32(input)?;
    let (input, nreloc) = le_u32(input)?;
    let (input, flags) = le_u32(input)?;
    let (input, reserved1) = le_u32(input)?;
    let (input, reserved2) = le_u32(input)?;

    Ok((
        input,
        Section32 {
            sectname: *array_ref![sectname, 0, 16],
            segname: *array_ref![segname, 0, 16],
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags,
            reserved1,
            reserved2,
        },
    ))
}

// Parsing function for Mach-O 64bit Section
fn parse_section_64(input: &[u8]) -> IResult<&[u8], Section64> {
    let (input, sectname) = take(16usize)(input)?;
    let (input, segname) = take(16usize)(input)?;
    let (input, addr) = le_u64(input)?;
    let (input, size) = le_u64(input)?;
    let (input, offset) = le_u32(input)?;
    let (input, align) = le_u32(input)?;
    let (input, reloff) = le_u32(input)?;
    let (input, nreloc) = le_u32(input)?;
    let (input, flags) = le_u32(input)?;
    let (input, reserved1) = le_u32(input)?;
    let (input, reserved2) = le_u32(input)?;
    let (input, reserved3) = le_u32(input)?;

    Ok((
        input,
        Section64 {
            sectname: *array_ref![sectname, 0, 16],
            segname: *array_ref![segname, 0, 16],
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags,
            reserved1,
            reserved2,
            reserved3,
        },
    ))
}

// Parse Mach-O commands
fn parse_macho_commands(
    data: &[u8],
    header: &MachOHeader64,
    macho_proto: &mut Macho,
) -> u64 {
    let header_size = if is_32_bit(header.magic) {
        std::mem::size_of::<MachOHeader32>()
    } else {
        std::mem::size_of::<MachOHeader64>()
    };

    let mut seg_count = 0;
    let mut command_offset = header_size;

    for _ in 0..header.ncmds {
        // Check if remaining data is not less than size of LoadCommand
        if data.len() - command_offset < std::mem::size_of::<LoadCommand>() {
            break;
        }

        // Parse load commands from Mach-O file
        let command_data = &data[command_offset..];
        if let Ok((_, mut command)) = parse_load_command(command_data) {
            if should_swap_bytes(header.magic) {
                swap_load_command(&mut command);
            }

            // Check if cmdsize is not less than size of LoadCommand
            if command.cmdsize < std::mem::size_of::<LoadCommand>() as u32 {
                break;
            }

            // Check if remaining data is not less than cmdsize
            if data.len() - command_offset < command.cmdsize as usize {
                break;
            }

            // Handle supported commands
            match command.cmd {
                LC_SEGMENT => {
                    handle_segment_command(
                        command_data,
                        command.cmdsize as usize,
                        &mut seg_count,
                        macho_proto,
                    );
                }
                LC_SEGMENT_64 => {
                    handle_segment_command_64(
                        command_data,
                        command.cmdsize as usize,
                        &mut seg_count,
                        macho_proto,
                    );
                }
                _ => {}
            }

            // Continue to next command offset
            command_offset += command.cmdsize as usize;
        } else {
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
        println!("Header:");
        println!("Magic: 0x{:x}", parsed_header.magic);
        println!("CPU Type: {}", parsed_header.cputype);
        println!("CPU Subtype: {}", parsed_header.cpusubtype);
        println!("File Type: {}", parsed_header.filetype);
        println!("Number of Commands: {}", parsed_header.ncmds);
        println!("Size of Commands: {}", parsed_header.sizeofcmds);
        println!("Flags: 0x{:x}", parsed_header.flags);
        println!("Reserved: 0x{:x}", parsed_header.reserved);
        println!();

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
    // Create an empty instance of the Mach-O protobuf
    let mut macho_proto = Macho::new();

    // Get a &[u8] slice with the content of the file being scanned.
    let data = ctx.scanned_data();

    // If data is too short to be valid Mach-O file, return empty protobuf
    if data.len() < VALID_MACHO_LENGTH {
        println!("Data is too short to be a valid Mach-O file.");
        return macho_proto;
    }

    // parse basic Mach-O file
    if is_macho_file_block(data) {
        parse_macho_file(data, &mut macho_proto);
    }

    if is_fat_macho_file_block(data) {
        //parse_fat_macho_file(data, &mut macho_proto);
    }

    macho_proto
}
