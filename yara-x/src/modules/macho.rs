use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

#[cfg(feature = "logging")]
use log::*;

use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};
use nom::{bytes::complete::take, multi::count, number::complete::*, IResult};
use thiserror::Error;

// Mach-O file needs to have at least header of size 28 to be considered correct
// Real minimum size of Mach-O file would be higher
const VALID_MACHO_LENGTH: usize = 28;

// Define Mach-O constats used in parsing
// as it is problematic to get those from proto destriptors
const MH_MAGIC: u32 = 0xfeedface;
const MH_CIGAM: u32 = 0xcefaedfe;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;

// Define Mach-O FAT header constants
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;
const FAT_MAGIC_64: u32 = 0xcafebabf;
const FAT_CIGAM_64: u32 = 0xbfbafeca;

// Define Mach-O CPU type constants
const CPU_TYPE_MC680X0: u32 = 0x00000006;
const CPU_TYPE_X86: u32 = 0x00000007;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM: u32 = 0x0000000c;
const CPU_TYPE_ARM64: u32 = 0x0100000c;
const CPU_TYPE_MC88000: u32 = 0x0000000d;
const CPU_TYPE_SPARC: u32 = 0x0000000e;
const CPU_TYPE_POWERPC: u32 = 0x00000012;
const CPU_TYPE_POWERPC64: u32 = 0x01000012;

// Define Mach-O load commands
const LC_SEGMENT: u32 = 0x00000001;
const LC_UNIXTHREAD: u32 = 0x00000005;
const LC_SEGMENT_64: u32 = 0x00000019;
const LC_MAIN: u32 = 0x80000028;

// Add error types
#[derive(Error, Debug)]
pub enum MachoError {
    #[error("File is too small")]
    FileTooSmall,

    #[error("Unsupported  cputype in header")]
    UnsupportedCPUType,

    #[error("File section is too small to contain `{0}`")]
    FileSectionTooSmall(String),

    #[error("`{0}` value not present in header")]
    MissingHeaderValue(String),

    #[error("Parsing error: {0}")]
    ParsingError(String),
}

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

// Fat header struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct FatHeader {
    magic: u32,
    nfat_arch: u32,
}

// 32bit Fat arch struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct FatArch32 {
    cputype: u32,
    cpusubtype: u32,
    offset: u32,
    size: u32,
    align: u32,
}

// 64bit Fat arch struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct FatArch64 {
    cputype: u32,
    cpusubtype: u32,
    offset: u64,
    size: u64,
    align: u32,
    reserved: u32,
}

// Load Command struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

// Segment Command 32bit struct
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

// Segment Command 64bit struct
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

// Segment Section 32bit struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct SegmentSection32 {
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

// Segment section 64bit struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct SegmentSection64 {
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

// Thread Command struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct ThreadCommand {
    cmd: u32,
    cmdsize: u32,
    flavor: u32,
    count: u32,
}

// Entry Point struct
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct EntryPointCommand {
    cmd: u32,
    cmdsize: u32,
    entryoff: u64,
    stacksize: u64,
}

// X86 CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct X86ThreadState {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    edi: u32,
    esi: u32,
    ebp: u32,
    esp: u32,
    ss: u32,
    eflags: u32,
    eip: u32,
    cs: u32,
    ds: u32,
    es: u32,
    fs: u32,
    gs: u32,
}

// ARM CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct ARMThreadState {
    r: Vec<u32>,
    sp: u32,
    lr: u32,
    pc: u32,
    cpsr: u32,
}

// SPARC CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct SPARCThreadState {
    psr: u32,
    pc: u32,
    npc: u32,
    y: u32,
    g: Vec<u32>,
    o: Vec<u32>,
}

// PPC CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct PPCThreadState {
    srr0: u32,
    srr1: u32,
    r: Vec<u32>,
    cr: u32,
    xer: u32,
    lr: u32,
    ctr: u32,
    mq: u32,
    vrsavead: u32,
}

// M68K ThreadState CPU struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct M68KThreadState {
    dreg: Vec<u32>,
    areg: Vec<u32>,
    pad: u16,
    sr: u16,
    pc: u32,
}

// M88K CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct M88KThreadState {
    r: Vec<u32>,
    xip: u32,
    xip_in_bd: u32,
    nip: u32,
}

// X86 64bit CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct X86ThreadState64 {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    cs: u64,
    fs: u64,
    gs: u64,
}

// ARM64 CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct ARMThreadState64 {
    r: Vec<u64>,
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
}

// PPC64 CPU ThreadState struct
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct PPCThreadState64 {
    srr0: u64,
    srr1: u64,
    r: Vec<u64>,
    cr: u32,
    xer: u64,
    lr: u64,
    ctr: u64,
    vrsave: u32,
}

// Get magic constant from Mach-O file
fn parse_magic(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
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
    magic == MH_MAGIC || magic == MH_CIGAM
}

// Determine if the fat arch is 32-bit based on its size
fn fat_is_32(magic: u32) -> bool {
    magic == FAT_MAGIC || magic == FAT_CIGAM
}

// If given file is BigEndian we want to swap bytes to LittleEndian
// If file is already in LittleEndian format return false
fn should_swap_bytes(magic: u32) -> bool {
    matches!(magic, MH_CIGAM | MH_CIGAM_64 | FAT_CIGAM | FAT_CIGAM_64)
}

// Change Mach-O RVA to offset
fn macho_rva_to_offset(address: u64, macho_file: &File) -> Option<u64> {
    for segment in &macho_file.segments {
        if let (Some(start), Some(vmsize), Some(fileoff)) =
            (segment.vmaddr, segment.vmsize, segment.fileoff)
        {
            let end = start + vmsize;

            if address >= start && address < end {
                return Some(fileoff + (address - start));
            }
        }
    }

    None
}

// Change Mach-O offset to RVA
fn macho_offset_to_rva(offset: u64, macho_file: &File) -> Option<u64> {
    for segment in &macho_file.segments {
        if let (Some(start), Some(filesize), Some(vmaddr)) =
            (segment.fileoff, segment.filesize, segment.vmaddr)
        {
            let end = start + filesize;

            if offset >= start && offset < end {
                return Some(vmaddr + (offset - start));
            }
        }
    }

    None
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

// Swap Mach-O segment section for 32bit files
fn swap_segment_section(section: &mut SegmentSection32) {
    section.addr = BigEndian::read_u32(&section.addr.to_le_bytes());
    section.size = BigEndian::read_u32(&section.size.to_le_bytes());
    section.offset = BigEndian::read_u32(&section.offset.to_le_bytes());
    section.align = BigEndian::read_u32(&section.align.to_le_bytes());
    section.reloff = BigEndian::read_u32(&section.reloff.to_le_bytes());
    section.nreloc = BigEndian::read_u32(&section.nreloc.to_le_bytes());
    section.flags = BigEndian::read_u32(&section.flags.to_le_bytes());
    section.reserved1 = BigEndian::read_u32(&section.reserved1.to_le_bytes());
    section.reserved2 = BigEndian::read_u32(&section.reserved2.to_le_bytes());
}

// Swap Mach-O segment section for 64bit files
fn swap_segment_section_64(section: &mut SegmentSection64) {
    section.addr = BigEndian::read_u64(&section.addr.to_le_bytes());
    section.size = BigEndian::read_u64(&section.size.to_le_bytes());
    section.offset = BigEndian::read_u32(&section.offset.to_le_bytes());
    section.align = BigEndian::read_u32(&section.align.to_le_bytes());
    section.reloff = BigEndian::read_u32(&section.reloff.to_le_bytes());
    section.nreloc = BigEndian::read_u32(&section.nreloc.to_le_bytes());
    section.flags = BigEndian::read_u32(&section.flags.to_le_bytes());
    section.reserved1 = BigEndian::read_u32(&section.reserved1.to_le_bytes());
    section.reserved2 = BigEndian::read_u32(&section.reserved2.to_le_bytes());
    section.reserved3 = BigEndian::read_u32(&section.reserved2.to_le_bytes());
}

// Swap Mach-O entrypoint command section
fn swap_entry_point_command(section: &mut EntryPointCommand) {
    section.cmd = BigEndian::read_u32(&section.cmd.to_le_bytes());
    section.cmdsize = BigEndian::read_u32(&section.cmdsize.to_le_bytes());
    section.entryoff = BigEndian::read_u64(&section.entryoff.to_le_bytes());
    section.stacksize = BigEndian::read_u64(&section.stacksize.to_le_bytes());
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

// Parse FAT header
fn parse_fat_header(input: &[u8]) -> IResult<&[u8], FatHeader> {
    let (input, magic) = be_u32(input)?;
    let (input, nfat_arch) = be_u32(input)?;
    Ok((input, FatHeader { magic, nfat_arch }))
}

// Parse FAT architecture for 32-bit
fn parse_fat_arch_32(input: &[u8]) -> IResult<&[u8], FatArch32> {
    let (input, cputype) = be_u32(input)?;
    let (input, cpusubtype) = be_u32(input)?;
    let (input, offset) = be_u32(input)?;
    let (input, size) = be_u32(input)?;
    let (input, align) = be_u32(input)?;

    Ok((input, FatArch32 { cputype, cpusubtype, offset, size, align }))
}

// Parse FAT architecture for 64-bit
fn parse_fat_arch_64(input: &[u8]) -> IResult<&[u8], FatArch64> {
    let (input, cputype) = be_u32(input)?;
    let (input, cpusubtype) = be_u32(input)?;
    let (input, offset) = be_u64(input)?;
    let (input, size) = be_u64(input)?;
    let (input, align) = be_u32(input)?;
    let (input, reserved) = be_u32(input)?;

    Ok((
        input,
        FatArch64 { cputype, cpusubtype, offset, size, align, reserved },
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
fn parse_section(input: &[u8]) -> IResult<&[u8], SegmentSection32> {
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
        SegmentSection32 {
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
fn parse_section_64(input: &[u8]) -> IResult<&[u8], SegmentSection64> {
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
        SegmentSection64 {
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

// Parsing function for Mach-O Thread command
fn parse_thread_command(input: &[u8]) -> IResult<&[u8], ThreadCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, flavor) = le_u32(input)?;
    let (input, count) = le_u32(input)?;

    Ok((input, ThreadCommand { cmd, cmdsize, flavor, count }))
}

// Parsing function for Mach-O Thread command
fn parse_entry_point_command(
    input: &[u8],
) -> IResult<&[u8], EntryPointCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, entryoff) = le_u64(input)?;
    let (input, stacksize) = le_u64(input)?;

    Ok((input, EntryPointCommand { cmd, cmdsize, entryoff, stacksize }))
}

// Parsing function for X86 CPU struct
fn parse_x86_thread_state(input: &[u8]) -> IResult<&[u8], X86ThreadState> {
    let (input, eax) = le_u32(input)?;
    let (input, ebx) = le_u32(input)?;
    let (input, ecx) = le_u32(input)?;
    let (input, edx) = le_u32(input)?;
    let (input, edi) = le_u32(input)?;
    let (input, esi) = le_u32(input)?;
    let (input, ebp) = le_u32(input)?;
    let (input, esp) = le_u32(input)?;
    let (input, ss) = le_u32(input)?;
    let (input, eflags) = le_u32(input)?;
    let (input, eip) = le_u32(input)?;
    let (input, cs) = le_u32(input)?;
    let (input, ds) = le_u32(input)?;
    let (input, es) = le_u32(input)?;
    let (input, fs) = le_u32(input)?;
    let (input, gs) = le_u32(input)?;

    Ok((
        input,
        X86ThreadState {
            eax,
            ebx,
            ecx,
            edx,
            edi,
            esi,
            ebp,
            esp,
            ss,
            eflags,
            eip,
            cs,
            ds,
            es,
            fs,
            gs,
        },
    ))
}

// Parsing function for ARM CPU struct
fn parse_arm_thread_state(input: &[u8]) -> IResult<&[u8], ARMThreadState> {
    let (input, r) = count(le_u32, 13)(input)?;
    let (input, sp) = le_u32(input)?;
    let (input, lr) = le_u32(input)?;
    let (input, pc) = le_u32(input)?;
    let (input, cpsr) = le_u32(input)?;

    Ok((input, ARMThreadState { r, sp, lr, pc, cpsr }))
}

// Parsing function for PPC CPU struct
fn parse_ppc_thread_state(input: &[u8]) -> IResult<&[u8], PPCThreadState> {
    let (input, srr0) = le_u32(input)?;
    let (input, srr1) = le_u32(input)?;
    let (input, r) = count(le_u32, 32)(input)?;
    let (input, cr) = le_u32(input)?;
    let (input, xer) = le_u32(input)?;
    let (input, lr) = le_u32(input)?;
    let (input, ctr) = le_u32(input)?;
    let (input, mq) = le_u32(input)?;
    let (input, vrsavead) = le_u32(input)?;

    Ok((
        input,
        PPCThreadState { srr0, srr1, r, cr, xer, lr, ctr, mq, vrsavead },
    ))
}

// Parsing function for SPARC CPU struct
fn parse_sparc_thread_state(input: &[u8]) -> IResult<&[u8], SPARCThreadState> {
    let (input, psr) = le_u32(input)?;
    let (input, pc) = le_u32(input)?;
    let (input, npc) = le_u32(input)?;
    let (input, y) = le_u32(input)?;
    let (input, g) = count(le_u32, 7)(input)?;
    let (input, o) = count(le_u32, 7)(input)?;

    Ok((input, SPARCThreadState { psr, pc, npc, y, g, o }))
}

// Parsing function for M68K CPU struct
fn parse_m68k_thread_state(input: &[u8]) -> IResult<&[u8], M68KThreadState> {
    let (input, dreg) = count(le_u32, 8)(input)?;
    let (input, areg) = count(le_u32, 8)(input)?;
    let (input, pad) = le_u16(input)?;
    let (input, sr) = le_u16(input)?;
    let (input, pc) = le_u32(input)?;

    Ok((input, M68KThreadState { dreg, areg, pad, sr, pc }))
}

// Parsing function for M88K CPU struct
fn parse_m88k_thread_state(input: &[u8]) -> IResult<&[u8], M88KThreadState> {
    let (input, r) = count(le_u32, 31)(input)?;
    let (input, xip) = le_u32(input)?;
    let (input, xip_in_bd) = le_u32(input)?;
    let (input, nip) = le_u32(input)?;

    Ok((input, M88KThreadState { r, xip, xip_in_bd, nip }))
}

// Parsing function for X86 64bit CPU struct
fn parse_x86_thread_state64(input: &[u8]) -> IResult<&[u8], X86ThreadState64> {
    let (input, rax) = le_u64(input)?;
    let (input, rbx) = le_u64(input)?;
    let (input, rcx) = le_u64(input)?;
    let (input, rdx) = le_u64(input)?;
    let (input, rdi) = le_u64(input)?;
    let (input, rsi) = le_u64(input)?;
    let (input, rbp) = le_u64(input)?;
    let (input, rsp) = le_u64(input)?;
    let (input, r8) = le_u64(input)?;
    let (input, r9) = le_u64(input)?;
    let (input, r10) = le_u64(input)?;
    let (input, r11) = le_u64(input)?;
    let (input, r12) = le_u64(input)?;
    let (input, r13) = le_u64(input)?;
    let (input, r14) = le_u64(input)?;
    let (input, r15) = le_u64(input)?;
    let (input, rip) = le_u64(input)?;
    let (input, rflags) = le_u64(input)?;
    let (input, cs) = le_u64(input)?;
    let (input, fs) = le_u64(input)?;
    let (input, gs) = le_u64(input)?;

    Ok((
        input,
        X86ThreadState64 {
            rax,
            rbx,
            rcx,
            rdx,
            rdi,
            rsi,
            rbp,
            rsp,
            r8,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
            rip,
            rflags,
            cs,
            fs,
            gs,
        },
    ))
}

// Parsing function for ARM 64bit CPU struct
fn parse_arm_thread_state64(input: &[u8]) -> IResult<&[u8], ARMThreadState64> {
    let (input, r) = count(le_u64, 29)(input)?;
    let (input, fp) = le_u64(input)?;
    let (input, lr) = le_u64(input)?;
    let (input, sp) = le_u64(input)?;
    let (input, pc) = le_u64(input)?;
    let (input, cpsr) = le_u32(input)?;

    Ok((input, ARMThreadState64 { r, fp, lr, sp, pc, cpsr }))
}

// Parsing function for PPC 64bit CPU struct
fn parse_ppc_thread_state64(input: &[u8]) -> IResult<&[u8], PPCThreadState64> {
    let (input, srr0) = le_u64(input)?;
    let (input, srr1) = le_u64(input)?;
    let (input, r) = count(le_u64, 32)(input)?;
    let (input, cr) = le_u32(input)?;
    let (input, xer) = le_u64(input)?;
    let (input, lr) = le_u64(input)?;
    let (input, ctr) = le_u64(input)?;
    let (input, vrsave) = le_u32(input)?;

    Ok((input, PPCThreadState64 { srr0, srr1, r, cr, xer, lr, ctr, vrsave }))
}

// Handle the LC_SEGMENT command
fn handle_segment_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // Check if segment size is not less than SegmentCommand32 struct size
    if size < std::mem::size_of::<SegmentCommand32>() {
        return Err(MachoError::FileSectionTooSmall(
            "SegmentCommand32".to_string(),
        ));
    }

    // Parse segment command data
    let (remaining_data, mut sg) = parse_segment_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_segment_command(&mut sg);
    }

    // Populate protobuf segment section for 32bit files
    let mut segment = Segment {
        cmd: Some(sg.cmd),
        cmdsize: Some(sg.cmdsize),
        segname: Some(
            std::str::from_utf8(&sg.segname).unwrap_or_default().to_string(),
        ),
        vmaddr: Some(sg.vmaddr as u64),
        vmsize: Some(sg.vmsize as u64),
        fileoff: Some(sg.fileoff as u64),
        filesize: Some(sg.filesize as u64),
        maxprot: Some(sg.maxprot),
        initprot: Some(sg.initprot),
        nsects: Some(sg.nsects),
        flags: Some(sg.flags),
        sections: Vec::new(),
        ..Default::default()
    };

    // Set the section fields in the 32bit Macho-O segment
    let mut sections_data = remaining_data;
    for _ in 0..sg.nsects {
        let (remaining_sections, mut sec) = parse_section(sections_data)
            .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
        if should_swap_bytes(
            macho_file
                .magic
                .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
        ) {
            swap_segment_section(&mut sec);
        }

        // Populate protobuf section for 32bit files
        let section = Section {
            segname: Some(
                std::str::from_utf8(&sec.segname)
                    .unwrap_or_default()
                    .to_string(),
            ),
            sectname: Some(
                std::str::from_utf8(&sec.sectname)
                    .unwrap_or_default()
                    .to_string(),
            ),
            addr: Some(sec.addr as u64),
            size: Some(sec.size as u64),
            offset: Some(sec.offset),
            align: Some(sec.align),
            reloff: Some(sec.reloff),
            nreloc: Some(sec.nreloc),
            flags: Some(sec.flags),
            reserved1: Some(sec.reserved1),
            reserved2: Some(sec.reserved2),
            ..Default::default()
        };

        segment.sections.push(section);

        sections_data = remaining_sections;
    }

    // Push segments with sections into protobuf
    macho_file.segments.push(segment);

    Ok(())
}

// Handle the LC_SEGMENT_64 command
fn handle_segment_command_64(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // Check if segment size is not less than SegmentCommand64 struct size
    if size < std::mem::size_of::<SegmentCommand64>() {
        return Err(MachoError::FileSectionTooSmall(
            "SegmentCommand64".to_string(),
        ));
    }

    // Parse segment command data
    let (remaining_data, mut sg) = parse_segment_command_64(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_segment_command_64(&mut sg);
    }

    // Populate protobuf segment section for 64bit files
    let mut segment = Segment {
        cmd: Some(sg.cmd),
        cmdsize: Some(sg.cmdsize),
        segname: Some(
            std::str::from_utf8(&sg.segname).unwrap_or_default().to_string(),
        ),
        vmaddr: Some(sg.vmaddr),
        vmsize: Some(sg.vmsize),
        fileoff: Some(sg.fileoff),
        filesize: Some(sg.filesize),
        maxprot: Some(sg.maxprot),
        initprot: Some(sg.initprot),
        nsects: Some(sg.nsects),
        flags: Some(sg.flags),
        sections: Vec::new(),
        ..Default::default()
    };

    // Set the section fields in the 64bit Macho-O segment
    let mut sections_data = remaining_data;
    for _ in 0..sg.nsects {
        let (remaining_sections, mut sec) = parse_section_64(sections_data)
            .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
        if should_swap_bytes(
            macho_file
                .magic
                .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
        ) {
            swap_segment_section_64(&mut sec);
        }

        // Populate protobuf section for 64bit files
        let section = Section {
            segname: Some(
                std::str::from_utf8(&sec.segname)
                    .unwrap_or_default()
                    .to_string(),
            ),
            sectname: Some(
                std::str::from_utf8(&sec.sectname)
                    .unwrap_or_default()
                    .to_string(),
            ),
            addr: Some(sec.addr),
            size: Some(sec.size),
            offset: Some(sec.offset),
            align: Some(sec.align),
            reloff: Some(sec.reloff),
            nreloc: Some(sec.nreloc),
            flags: Some(sec.flags),
            reserved1: Some(sec.reserved1),
            reserved2: Some(sec.reserved2),
            reserved3: Some(sec.reserved3),
            ..Default::default()
        };

        segment.sections.push(section);
        sections_data = remaining_sections;
    }

    // Push segments with sections into protobuf
    macho_file.segments.push(segment);

    Ok(())
}

// Handle UNIXTHREAD Command (older CPUs, replaced by LC_MAIN)
fn handle_unixthread(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<ThreadCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "ThreadCommand".to_string(),
        ));
    }

    // Parse thread command
    let (remaining_data, thread_cmd) = parse_thread_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    // Check command size
    let command_size = std::cmp::min(size, thread_cmd.cmdsize as usize);
    if command_size < std::mem::size_of::<ThreadCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "ThreadCommand".to_string(),
        ));
    }

    let thread_state_size =
        command_size - std::mem::size_of::<ThreadCommand>();
    let mut address: u64 = 0;
    let mut is64: bool = false;

    // Perform parsing according to cputype in header
    match macho_file
        .cputype
        .ok_or(MachoError::MissingHeaderValue("cputype".to_string()))?
    {
        CPU_TYPE_MC680X0 => {
            if thread_state_size >= std::mem::size_of::<M68KThreadState>() {
                let (_, state) = parse_m68k_thread_state(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.pc as u64;
            }
        }
        CPU_TYPE_MC88000 => {
            if thread_state_size >= std::mem::size_of::<M88KThreadState>() {
                let (_, state) = parse_m88k_thread_state(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.xip as u64;
            }
        }
        CPU_TYPE_SPARC => {
            if thread_state_size >= std::mem::size_of::<SPARCThreadState>() {
                let (_, state) = parse_sparc_thread_state(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.pc as u64;
            }
        }
        CPU_TYPE_POWERPC => {
            if thread_state_size >= std::mem::size_of::<PPCThreadState>() {
                let (_, state) = parse_ppc_thread_state(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.srr0 as u64;
            }
        }
        CPU_TYPE_X86 => {
            if thread_state_size >= std::mem::size_of::<X86ThreadState>() {
                let (_, state) = parse_x86_thread_state(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.eip as u64;
            }
        }
        CPU_TYPE_ARM => {
            if thread_state_size >= std::mem::size_of::<ARMThreadState>() {
                let (_, state) = parse_arm_thread_state(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.pc as u64;
            }
        }
        CPU_TYPE_X86_64 => {
            if thread_state_size >= std::mem::size_of::<X86ThreadState64>() {
                let (_, state) = parse_x86_thread_state64(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.rip;
                is64 = true;
            }
        }
        CPU_TYPE_ARM64 => {
            if thread_state_size >= std::mem::size_of::<ARMThreadState64>() {
                let (_, state) = parse_arm_thread_state64(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.pc;
                is64 = true;
            }
        }
        CPU_TYPE_POWERPC64 => {
            if thread_state_size >= std::mem::size_of::<PPCThreadState64>() {
                let (_, state) = parse_ppc_thread_state64(remaining_data)
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                address = state.srr0;
                is64 = true;
            }
        }
        _ => return Err(MachoError::UnsupportedCPUType),
    }

    // Swap bytes if neccessary
    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        address = if is64 {
            address.swap_bytes()
        } else {
            (address as u32).swap_bytes() as u64
        };
    }

    // TODO: COMPILER FLAGS
    macho_file.entry_point = macho_rva_to_offset(address, macho_file);

    Ok(())
}

// Handle MAIN command
fn handle_main(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // Check size
    if size < std::mem::size_of::<EntryPointCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "EntryPointCommand".to_string(),
        ));
    }

    // Parse main command
    let (_, mut entrypoint_cmd) = parse_entry_point_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    // Swap bytes if neccesarry
    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_entry_point_command(&mut entrypoint_cmd);
    }

    // TODO: COMPILER FLAGS
    if false {
        macho_file.entry_point =
            macho_offset_to_rva(entrypoint_cmd.entryoff, macho_file);
    } else {
        macho_file.set_entry_point(entrypoint_cmd.entryoff);
    }

    macho_file.set_stack_size(entrypoint_cmd.stacksize);

    Ok(())
}

// Handle Command Segment in Mach-O files according to Load Command value
fn handle_command(
    cmd: u32,
    cmdsize: usize,
    command_data: &[u8],
    macho_file: &mut File,
    process_segments: bool,
) -> Result<u64, MachoError> {
    let mut seg_count = 0;

    // Handle segment commands and increment segment count
    if process_segments {
        match cmd {
            LC_SEGMENT => {
                handle_segment_command(command_data, cmdsize, macho_file)?;
                seg_count += 1;
            }
            LC_SEGMENT_64 => {
                handle_segment_command_64(command_data, cmdsize, macho_file)?;
                seg_count += 1;
            }
            _ => {}
        }
    // Handle rest of commands
    } else {
        match cmd {
            LC_UNIXTHREAD => {
                handle_unixthread(command_data, cmdsize, macho_file)?;
            }
            LC_MAIN => {
                handle_main(command_data, cmdsize, macho_file)?;
            }
            _ => {}
        }
    }

    Ok(seg_count)
}

// Parse Mach-O commands
fn parse_macho_commands(
    data: &[u8],
    macho_file: &mut File,
    process_segments: bool,
) -> Result<u64, MachoError> {
    let header_size = if is_32_bit(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        std::mem::size_of::<MachOHeader32>()
    } else {
        std::mem::size_of::<MachOHeader64>()
    };

    let mut seg_count = 0;
    let mut command_offset = header_size;

    // Loop over Mach-O commands
    for _ in 0..macho_file
        .ncmds
        .ok_or(MachoError::MissingHeaderValue("ncmds".to_string()))?
    {
        // Check if remaining data is not less than size of LoadCommand
        if data.len() - command_offset < std::mem::size_of::<LoadCommand>() {
            break;
        }

        // Parse load commands from Mach-O file
        let command_data = &data[command_offset..];
        let (_, mut command) = parse_load_command(command_data)
            .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
        if should_swap_bytes(
            macho_file
                .magic
                .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
        ) {
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

        seg_count += handle_command(
            command.cmd,
            command.cmdsize as usize,
            command_data,
            macho_file,
            process_segments,
        )?;

        // Continue to next command offset
        command_offset += command.cmdsize as usize;
    }

    Ok(seg_count)
}

// Parse basic Mach-O file
fn parse_macho_file(data: &[u8]) -> Result<File, MachoError> {
    let mut macho_file = File::default();
    // File is too small to contain Mach-O header
    if data.len() < std::mem::size_of::<MachOHeader64>() {
        return Err(MachoError::FileTooSmall);
    }

    let (_, mut parsed_header) = parse_macho_header(data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
    // Byte conversion (swap) if necessary
    if should_swap_bytes(parsed_header.magic) {
        swap_mach_header(&mut parsed_header);
    }

    // Populate protobuf header section
    macho_file.set_magic(parsed_header.magic);
    macho_file.set_cputype(parsed_header.cputype);
    macho_file.set_cpusubtype(parsed_header.cpusubtype);
    macho_file.set_filetype(parsed_header.filetype);
    macho_file.set_ncmds(parsed_header.ncmds);
    macho_file.set_sizeofcmds(parsed_header.sizeofcmds);
    macho_file.set_flags(parsed_header.flags);
    if !is_32_bit(parsed_header.magic) {
        macho_file.set_reserved(parsed_header.reserved);
    }

    // Populate number of segments based on return type
    let number_of_segments =
        parse_macho_commands(data, &mut macho_file, true)?;
    macho_file.set_number_of_segments(number_of_segments);

    // Populate other fields
    parse_macho_commands(data, &mut macho_file, false)?;

    Ok(macho_file)
}

// Parse FAT Mach-O file
fn parse_fat_macho_file(
    data: &[u8],
    macho_proto: &mut Macho,
) -> Result<(), MachoError> {
    let (remaining_data, header) = parse_fat_header(data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    macho_proto.set_fat_magic(header.magic);
    macho_proto.set_nfat_arch(header.nfat_arch);

    // Depending on the size of the data, determine if it's a 32bit or 64bit Mach-O
    let fat_arch_size = if fat_is_32(header.magic) {
        std::mem::size_of::<FatArch32>()
    } else {
        std::mem::size_of::<FatArch64>()
    };

    // Loop through the nested array of fat_archs
    for i in 0..header.nfat_arch as usize {
        let arch_data = &remaining_data[i * fat_arch_size..];

        // Parse 32bit FAT headers
        if fat_is_32(header.magic) {
            let (_, arch) = parse_fat_arch_32(arch_data)
                .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

            let fat_arch_entry = FatArch {
                cputype: Some(arch.cputype),
                cpusubtype: Some(arch.cpusubtype),
                offset: Some(arch.offset as u64),
                size: Some(arch.size as u64),
                align: Some(arch.align),
                ..Default::default()
            };
            macho_proto.fat_arch.push(fat_arch_entry);

            // Parse nested data as basic Mach-O file
            let nested_file = parse_macho_file(
                &data
                    [arch.offset as usize..(arch.offset + arch.size) as usize],
            )?;
            macho_proto.file.push(nested_file);
        // Parse 64bit FAT headers
        } else {
            let (_, arch) = parse_fat_arch_64(arch_data)
                .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

            let fat_arch_entry = FatArch {
                cputype: Some(arch.cputype),
                cpusubtype: Some(arch.cpusubtype),
                offset: Some(arch.offset),
                size: Some(arch.size),
                align: Some(arch.align),
                reserved: Some(arch.reserved),
                ..Default::default()
            };
            macho_proto.fat_arch.push(fat_arch_entry);

            // Parse nested data as basic Mach-O file
            let nested_file = parse_macho_file(
                &data
                    [arch.offset as usize..(arch.offset + arch.size) as usize],
            )?;
            macho_proto.file.push(nested_file);
        }
    }

    Ok(())
}

// Helper function to print Option values or "NOT PRESENT"
fn print_option<T: std::fmt::Display>(opt: Option<T>) -> String {
    match opt {
        Some(val) => val.to_string(),
        None => "NOT PRESENT".to_string(),
    }
}

// Helper function to print Option values as hex or "NOT PRESENT"
fn print_option_hex<T: std::fmt::LowerHex>(opt: Option<T>) -> String {
    match opt {
        Some(val) => format!("0x{:x}", val),
        None => "NOT PRESENT".to_string(),
    }
}

// Debug printing
fn print_macho_info(macho_proto: &Macho) {
    println!("Header:");
    println!("Magic: {}", print_option_hex(macho_proto.magic));
    println!("CPU Type: {}", print_option(macho_proto.cputype));
    println!("CPU Subtype: {}", print_option(macho_proto.cpusubtype));
    println!("File Type: {}", print_option(macho_proto.filetype));
    println!("Number of Commands: {}", print_option(macho_proto.ncmds));
    println!("Size of Commands: {}", print_option(macho_proto.sizeofcmds));
    println!("Flags: {}", print_option_hex(macho_proto.flags));
    println!("Reserved: {}", print_option_hex(macho_proto.reserved));
    println!();

    // Print Segment Commands
    for segment in &macho_proto.segments {
        println!("Segment Commands:");
        println!("Command: {}", print_option_hex(segment.cmd));
        println!("Command Size: {}", print_option(segment.cmdsize));
        println!("Segment Name: {}", print_option(segment.segname.as_ref()));
        println!("VM Address: {}", print_option_hex(segment.vmaddr));
        println!("VM Size: {}", print_option_hex(segment.vmsize));
        println!("File Offset: {}", print_option(segment.fileoff));
        println!("File Size: {}", print_option(segment.filesize));
        println!("Max Protection: {}", print_option_hex(segment.maxprot));
        println!("Init Protection: {}", print_option_hex(segment.initprot));
        println!("Number of Sections: {}", print_option(segment.nsects));
        println!("Flags: {}", print_option_hex(segment.flags));
        // Print nested Segment Sections
        for section in &segment.sections {
            println!("Sections:");
            println!(
                "Segment Name: {}",
                print_option(section.segname.as_ref())
            );
            println!(
                "Section Name: {}",
                print_option(section.sectname.as_ref())
            );
            println!("Address: {}", print_option_hex(section.addr));
            println!("Size: {}", print_option_hex(section.size));
            println!("Offset: {}", print_option(section.offset));
            println!("Alignment: {}", print_option(section.align));
            println!("Relocation Offset: {}", print_option(section.reloff));
            println!(
                "Number of Relocations: {}",
                print_option(section.nreloc)
            );
            println!("Flags: {}", print_option_hex(section.flags));
            println!("Reserved 1: {}", print_option(section.reserved1));
            println!("Reserved 2: {}", print_option(section.reserved2));
            println!("Reserved 3: {}", print_option(section.reserved3));
            println!();
        }
        println!();
    }

    // Print Number of Segments
    println!(
        "Number of segments: {}",
        print_option(macho_proto.number_of_segments)
    );

    // Print Entry Point
    println!("Entry Point: {}", print_option(macho_proto.entry_point));

    // Print Stack Size
    println!("Stack Size: {}", print_option(macho_proto.stack_size));

    // FAT related printing:
    // Print Fat binary header info
    println!("Fat Binary Header:");
    println!("Fat Magic: {}", print_option_hex(macho_proto.fat_magic));
    println!(
        "Number of Fat Architectures: {}",
        print_option(macho_proto.nfat_arch)
    );
    println!();

    // Print each FatArch entry
    for fat_arch in &macho_proto.fat_arch {
        println!("Fat Architecture:");
        println!("CPU Type: {}", print_option(fat_arch.cputype));
        println!("CPU Subtype: {}", print_option(fat_arch.cpusubtype));
        println!("Offset: {}", print_option_hex(fat_arch.offset));
        println!("Size: {}", print_option_hex(fat_arch.size));
        println!("Align: {}", print_option(fat_arch.align));
        println!("Reserved: {}", print_option_hex(fat_arch.reserved));
        println!();
    }

    // Print nested Mach-O files
    for nested_file in &macho_proto.file {
        println!("Nested Mach-O File:");
        println!("Magic: {}", print_option_hex(nested_file.magic));
        println!("CPU Type: {}", print_option(nested_file.cputype));
        println!("CPU Subtype: {}", print_option(nested_file.cpusubtype));
        println!("File Type: {}", print_option(nested_file.filetype));
        println!("Number of Commands: {}", print_option(nested_file.ncmds));
        println!("Size of Commands: {}", print_option(nested_file.sizeofcmds));
        println!("Flags: {}", print_option_hex(nested_file.flags));
        println!("Reserved: {}", print_option_hex(nested_file.reserved));
        println!();

        // Print nested Segment Commands
        for segment in &nested_file.segments {
            println!("Segment Commands:");
            println!("Command: {}", print_option_hex(segment.cmd));
            println!("Command Size: {}", print_option(segment.cmdsize));
            println!(
                "Segment Name: {}",
                print_option(segment.segname.as_ref())
            );
            println!("VM Address: {}", print_option_hex(segment.vmaddr));
            println!("VM Size: {}", print_option_hex(segment.vmsize));
            println!("File Offset: {}", print_option(segment.fileoff));
            println!("File Size: {}", print_option(segment.filesize));
            println!("Max Protection: {}", print_option_hex(segment.maxprot));
            println!(
                "Init Protection: {}",
                print_option_hex(segment.initprot)
            );
            println!("Number of Sections: {}", print_option(segment.nsects));
            println!("Flags: {}", print_option_hex(segment.flags));
            // Print nested Segment Sections
            for section in &segment.sections {
                println!("Sections:");
                println!(
                    "Segment Name: {}",
                    print_option(section.segname.as_ref())
                );
                println!(
                    "Section Name: {}",
                    print_option(section.sectname.as_ref())
                );
                println!("Address: {}", print_option_hex(section.addr));
                println!("Size: {}", print_option_hex(section.size));
                println!("Offset: {}", print_option(section.offset));
                println!("Alignment: {}", print_option(section.align));
                println!(
                    "Relocation Offset: {}",
                    print_option(section.reloff)
                );
                println!(
                    "Number of Relocations: {}",
                    print_option(section.nreloc)
                );
                println!("Flags: {}", print_option_hex(section.flags));
                println!("Reserved 1: {}", print_option(section.reserved1));
                println!("Reserved 2: {}", print_option(section.reserved2));
                println!("Reserved 3: {}", print_option(section.reserved3));
                println!();
            }
            println!();
        }

        // Print number of segments, entry point, and stack size
        println!(
            "Number of segments: {}",
            print_option(nested_file.number_of_segments)
        );
        println!("Entry Point: {}", print_option(nested_file.entry_point));
        println!("Stack Size: {}", print_option(nested_file.stack_size));
        println!();
    }
}

// Get Mach-O file index in fat file by cputype field.
#[module_export(name = "file_index_for_arch")]
fn file_index_type(ctx: &mut ScanContext, type_arg: i64) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let Some(cputype) = arch.cputype {
                if cputype as i64 == type_arg {
                    return Some(i as i64);
                }
            }
        }
    }

    None
}

// Get Mach-O file index in fat file by cputype and cpusubtype fields.
#[module_export(name = "file_index_for_arch")]
fn file_index_subtype(
    ctx: &mut ScanContext,
    type_arg: i64,
    subtype_arg: i64,
) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let (Some(cputype), Some(cpusubtype)) =
                (arch.cputype, arch.cpusubtype)
            {
                if cputype as i64 == type_arg
                    && cpusubtype as i64 == subtype_arg
                {
                    return Some(i as i64);
                }
            }
        }
    }

    None
}

// Get real entry point offset for specific architecture in fat Mach-O.
#[module_export(name = "entry_point_for_arch")]
fn ep_for_arch_type(ctx: &mut ScanContext, type_arg: i64) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let Some(cputype) = arch.cputype {
                if cputype as i64 == type_arg {
                    let file_offset = arch.offset?;
                    let entry_point = macho.file.get(i)?.entry_point?;
                    return Some(file_offset as i64 + entry_point as i64);
                }
            }
        }
    }

    None
}

// Get real entry point offset for specific architecture in fat Mach-O.
#[module_export(name = "entry_point_for_arch")]
fn ep_for_arch_subtype(
    ctx: &mut ScanContext,
    type_arg: i64,
    subtype_arg: i64,
) -> Option<i64> {
    let macho = ctx.module_output::<Macho>()?;

    // Ensure nfat_arch is present
    let nfat = macho.nfat_arch?;

    // Iterate over fat_arch up to nfat entries
    for i in 0..nfat as usize {
        if let Some(arch) = macho.fat_arch.get(i) {
            if let (Some(cputype), Some(cpusubtype)) =
                (arch.cputype, arch.cpusubtype)
            {
                if cputype as i64 == type_arg
                    && cpusubtype as i64 == subtype_arg
                {
                    let file_offset = arch.offset?;
                    let entry_point = macho.file.get(i)?.entry_point?;
                    return Some(file_offset as i64 + entry_point as i64);
                }
            }
        }
    }

    None
}

#[module_main]
fn main(ctx: &ScanContext) -> Macho {
    // Create an empty instance of the Mach-O protobuf
    let mut macho_proto = Macho::new();

    // Get a &[u8] slice with the content of the file being scanned.
    let data = ctx.scanned_data();

    // If data is too short to be valid Mach-O file, return empty protobuf
    if data.len() < VALID_MACHO_LENGTH {
        #[cfg(feature = "logging")]
        error!("{}", MachoError::FileTooSmall);
        return macho_proto;
    }

    // Parse basic Mach-O file
    if is_macho_file_block(data) {
        match parse_macho_file(data) {
            // Parsing was successful, populate basic fields from parsed Mach-O structure
            Ok(file_data) => {
                macho_proto.magic = file_data.magic;
                macho_proto.cputype = file_data.cputype;
                macho_proto.cpusubtype = file_data.cpusubtype;
                macho_proto.filetype = file_data.filetype;
                macho_proto.ncmds = file_data.ncmds;
                macho_proto.sizeofcmds = file_data.sizeofcmds;
                macho_proto.flags = file_data.flags;
                macho_proto.reserved = file_data.reserved;
                macho_proto.number_of_segments = file_data.number_of_segments;
                macho_proto.segments = file_data.segments;
                macho_proto.entry_point = file_data.entry_point;
                macho_proto.stack_size = file_data.stack_size;
            }
            Err(_error) => {
                #[cfg(feature = "logging")]
                error!("Error while parsing macho file: {}", _error);
            }
        }
    }

    // Parse Mach-O FAT files
    if is_fat_macho_file_block(data) {
        if let Err(_error) = parse_fat_macho_file(data, &mut macho_proto) {
            #[cfg(feature = "logging")]
            error!("Error while parsing macho FAT file:{}", _error);
        }
    }

    print_macho_info(&macho_proto);
    macho_proto
}
