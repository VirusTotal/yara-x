//! Module that handles parsing of Mach-O files from ScanContext bytes
//! The implementation provides utility functions to determine
//! if a given binary data corresponds to a Mach-O file, and further
//! breaks down the data into relevant Mach-O structures and populates
//! both protobuf structure fields and constants. This together with
//! also exported functions can be later used in YARA rules.

use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};
use nom::{bytes::complete::take, multi::count, number::complete::*, IResult};
use protobuf::MessageField;
use thiserror::Error;

use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

#[cfg(test)]
mod tests;

#[cfg(feature = "logging")]
use log::*;

/// Mach-O file needs to have at least header of size 28 to be considered
/// correct Real minimum size of Mach-O file would be higher
const VALID_MACHO_LENGTH: usize = 28;

/// Define Mach-O constants used in parsing
/// as it is problematic to get those from proto descriptors
const MH_MAGIC: u32 = 0xfeedface;
const MH_CIGAM: u32 = 0xcefaedfe;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;

/// Define Mach-O FAT header constants
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;
const FAT_MAGIC_64: u32 = 0xcafebabf;
const FAT_CIGAM_64: u32 = 0xbfbafeca;

/// Define Mach-O CPU type constants
const CPU_TYPE_MC680X0: u32 = 0x00000006;
const CPU_TYPE_X86: u32 = 0x00000007;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM: u32 = 0x0000000c;
const CPU_TYPE_ARM64: u32 = 0x0100000c;
const CPU_TYPE_MC88000: u32 = 0x0000000d;
const CPU_TYPE_SPARC: u32 = 0x0000000e;
const CPU_TYPE_POWERPC: u32 = 0x00000012;
const CPU_TYPE_POWERPC64: u32 = 0x01000012;

/// Define Mach-O dynamic linker constant
const LC_REQ_DYLD: u32 = 0x80000000;

/// Define Mach-O load commands
const LC_SEGMENT: u32 = 0x00000001;
const LC_SYMTAB: u32 = 0x00000002;
const LC_UNIXTHREAD: u32 = 0x00000005;
const LC_DYSYMTAB: u32 = 0x0000000b;
const LC_LOAD_DYLIB: u32 = 0x0000000c;
const LC_ID_DYLIB: u32 = 0x0000000d;
const LC_LOAD_DYLINKER: u32 = 0x0000000e;
const LC_ID_DYLINKER: u32 = 0x0000000f;

const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_SEGMENT_64: u32 = 0x00000019;
const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
const LC_DYLD_INFO: u32 = 0x00000022;
const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
const LC_DYLD_ENVIRONMENT: u32 = 0x00000027;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
const LC_SOURCE_VERSION: u32 = 0x0000002a;

/// Enum that provides strongly-typed error system used in code
/// Represents all possible errors that can occur during Mach-O parsing
/// Each variant provides specific error details.
#[derive(Error, Debug)]
pub enum MachoError {
    #[error("File section is too small to contain `{0}`")]
    FileSectionTooSmall(String),

    #[error("File is too small")]
    FileTooSmall,

    #[error("`{0}` value not present in header")]
    MissingHeaderValue(String),

    #[error("Parsing error: {0}")]
    ParsingError(String),

    #[error("Unsupported  cputype in header")]
    UnsupportedCPUType,

    #[error("Integer overflow error")]
    Overflow,
}

/// Mach-O file structures that represent the file
/// and all relevant information about the file

/// `MachoHeader32`: Represents the header of a 32-bit Mach-O file.
/// Fields: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
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

/// `MachoHeader64`: Represents the header of a 64-bit Mach-O file.
/// Fields: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags,
/// reserved
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

/// `FatHeader`: Header for a fat Mach-O binary containing multiple
/// architectures. Fields: magic, nfat_arch
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct FatHeader {
    magic: u32,
    nfat_arch: u32,
}

/// `FatArch32`: Describes a 32-bit architecture in a fat binary.
/// Fields: cputype, cpusubtype, offset, size, align
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct FatArch32 {
    cputype: u32,
    cpusubtype: u32,
    offset: u32,
    size: u32,
    align: u32,
}

/// `FatArch64`: Describes a 64-bit architecture in a fat binary.
/// Fields: cputype, cpusubtype, offset, size, align, reserved
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

/// `LoadCommand`: Represents a load command in the Mach-O file.
/// Fields: cmd, cmdsize
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

/// `DyldInfoCommand`: Represents the dyld info load command in the Mach-O file.
/// Fields: cmd, cmdsize, rebase_off, rebase_size, bind_off, bind_size, weak_bind_off
/// weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size
#[derive(Debug, Default, Clone, Copy)]
struct DyldInfoCommand {
    cmd: u32,
    cmdsize: u32,
    rebase_off: u32,
    rebase_size: u32,
    bind_off: u32,
    bind_size: u32,
    weak_bind_off: u32,
    weak_bind_size: u32,
    lazy_bind_off: u32,
    lazy_bind_size: u32,
    export_off: u32,
    export_size: u32,
}

/// `SymtabCommand`: Represents a symbol table load command in the Mach-O file.
/// Fields: cmd, cmdsize, symoff, nsyms, stroff, strsize
#[derive(Debug, Default, Clone, Copy)]
struct SymtabCommand {
    cmd: u32,
    cmdsize: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

/// `DysymtabCommand`: Represents a dynamic symbol table
/// load command in the Mach-O file.
/// Fields: cmd, cmdsize, ilocalsym, nlocalsym, iextdefsym, nextdefsym,
/// tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms, indirectsymoff,
/// nindirectsyms, extreloff, nextrel, locreloff, nlocrel
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct DysymtabCommand {
    cmd: u32,
    cmdsize: u32,
    ilocalsym: u32,
    nlocalsym: u32,
    iextdefsym: u32,
    nextdefsym: u32,
    tocoff: u32,
    ntoc: u32,
    modtaboff: u32,
    nmodtab: u32,
    extrefsymoff: u32,
    nextrefsyms: u32,
    indirectsymoff: u32,
    nindirectsyms: u32,
    extreloff: u32,
    nextrel: u32,
    locreloff: u32,
    nlocrel: u32,
}

/// `SourceVersionCommand`: Represents a source version load command
/// in the Mach-O file.
/// Fields: cmd, cmdsize, version
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct SourceVersionCommand {
    cmd: u32,
    cmdsize: u32,
    version: u64,
}

/// `DylibObject`: Represents a dylib struct in the Mach-O file.
/// Fields: name, timestamp, current_version, compatibility_version
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct DylibObject {
    offset: u32,
    timestamp: u32,
    current_version: u32,
    compatibility_version: u32,
    name: Vec<u8>,
}

/// `DylibCommand`: Represents a dylib command in the Mach-O file.
/// Fields: cmd, cmdsize, dylib
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct DylibCommand {
    cmd: u32,
    cmdsize: u32,
    dylib: DylibObject,
}

/// `DylinkerCommand`: Represents an dynamic linker command in the Mach-O file.
/// Fields: cmd, cmdsize, name
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct DylinkerCommand {
    cmd: u32,
    cmdsize: u32,
    offset: u32,
    name: Vec<u8>,
}

/// `RPathCommand`: Represents an rpath command in the Mach-O file.
/// Fields: cmd, cmdsize, path
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct RPathCommand {
    cmd: u32,
    cmdsize: u32,
    offset: u32,
    path: Vec<u8>,
}

/// `SegmentCommand32`: Represents a 32-bit segment command in the Mach-O file.
/// Fields: cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot,
/// initprot, nsects, flags
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

/// `SegmentCommand64`: Represents a 64-bit segment command in the Mach-O file.
/// Fields: cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot,
/// initprot, nsects, flags
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

/// `SegmentSection32`: Represents a 32-bit section within a segment.
/// Fields: sectname, segname, addr, size, offset, align, reloff, nreloc,
/// flags, reserved1, reserved2
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

/// `SegmentSection64`: Represents a 64-bit section within a segment.
/// Fields: sectname, segname, addr, size, offset, align, reloff, nreloc,
/// flags, reserved1, reserved2, reserved3
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

/// `ThreadCommand`: Represents a thread command in the Mach-O file.
/// Fields: cmd, cmdsize, flavor, count
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct ThreadCommand {
    cmd: u32,
    cmdsize: u32,
    flavor: u32,
    count: u32,
}

/// `EntryPointCommand`: Represents the entry point command in the Mach-O file.
/// Fields: cmd, cmdsize, entryoff, stacksize
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct EntryPointCommand {
    cmd: u32,
    cmdsize: u32,
    entryoff: u64,
    stacksize: u64,
}

/// `X86ThreadState`: Represents the state of an x86 thread in the Mach-O file.
/// Fields: eax, ebx, ecx, edx, edi, esi, ebp, esp, ss, eflags, eip, cs, ds,
/// es, fs, gs
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

/// `ARMThreadState`: Represents the state of an ARM thread in a Mach-O file.
/// Fields: r, sp, lr, pc, cpsr
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct ARMThreadState {
    r: Vec<u32>,
    sp: u32,
    lr: u32,
    pc: u32,
    cpsr: u32,
}

/// `SPARCThreadState`: Represents the state of a SPARC thread in a Mach-O
/// file. Fields: psr, pc, npc, y, g, o
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

/// `PPCThreadState`: Represents the state of a PowerPC thread in a Mach-O
/// file. Fields: srr0, srr1, r, cr, xer, lr, ctr, mq, vrsavead
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

/// `M68KThreadState`: Represents the state of an M68K thread in a Mach-O file.
/// Fields: dreg, areg, pad, sr, pc
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct M68KThreadState {
    dreg: Vec<u32>,
    areg: Vec<u32>,
    pad: u16,
    sr: u16,
    pc: u32,
}

/// `M88KThreadState`: Represents the state of an M88K thread in a Mach-O file.
/// Fields: r, xip, xip_in_bd, nip
#[repr(C)]
#[derive(Debug, Default, Clone)]
struct M88KThreadState {
    r: Vec<u32>,
    xip: u32,
    xip_in_bd: u32,
    nip: u32,
}

/// `X86ThreadState64`: Represents the state of an x86-64 thread in a Mach-O
/// file. Fields: rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp, r8, r9, r10, r11,
/// r12, r13, r14, r15, rip, rflags, cs, fs, gs
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

/// `ARMThreadState64`: Represents the state of an ARM64 thread in a Mach-O
/// file. Fields: r, fp, lr, sp, pc, cpsr
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

/// `PPCThreadState64`: Represents the state of a PowerPC64 thread in a Mach-O
/// file. Fields: srr0, srr1, r, cr, xer, lr, ctr, vrsave
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

/// Parse the magic constant from a Mach-O file. The magic constant identifies
/// the file as a Mach-O file and indicates its endianness and architecture.
///
/// # Arguments
///
/// * `input`: A byte slice representing the start of the Mach-O file.
///
/// # Returns
///
/// An `IResult` with the remaining bytes after reading the magic constant
/// and the parsed 32-bit magic constant itself.
fn parse_magic(input: &[u8]) -> IResult<&[u8], u32> {
    le_u32(input)
}

/// Check if the provided data represents a basic Mach-O file.
///
/// # Arguments
///
/// * `data`: A byte slice to check.
///
/// # Returns
///
/// `true` if the data starts with a file Mach-O magic constant, `false`
/// otherwise.
fn is_macho_file_block(data: &[u8]) -> bool {
    match parse_magic(data) {
        Ok((_, magic)) => {
            matches!(magic, MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64)
        }
        _ => false,
    }
}

/// Check if the provided data represents a FAT Mach-O file.
///
/// # Arguments
///
/// * `data`: A byte slice to check.
///
/// # Returns
///
/// `true` if the data starts with a FAT Mach-O magic constant, `false`
/// otherwise.
fn is_fat_macho_file_block(data: &[u8]) -> bool {
    match parse_magic(data) {
        Ok((_, magic)) => matches!(
            magic,
            FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64
        ),
        _ => false,
    }
}

/// Determine if a given magic constant represents a 32-bit Mach-O file.
///
/// # Arguments
///
/// * `magic`: The magic constant to check.
///
/// # Returns
///
/// `true` if the magic constant represents a 32-bit Mach-O file, `false`
/// otherwise.
fn is_32_bit(magic: u32) -> bool {
    magic == MH_MAGIC || magic == MH_CIGAM
}

/// Determine if a given magic constant represents a 32-bit FAT arch.
///
/// # Arguments
///
/// * `magic`: The magic constant to check.
///
/// # Returns
///
/// `true` if the magic constant represents a 32-bit FAT arch, `false`
/// otherwise.
fn fat_is_32(magic: u32) -> bool {
    magic == FAT_MAGIC || magic == FAT_CIGAM
}

/// Check if bytes should be swapped based on the magic constant.
/// This is used to determine endianness.
///
/// # Arguments
///
/// * `magic`: The magic constant to check.
///
/// # Returns
///
/// `true` if bytes should be swapped (BigEndian format), `false` if they're
/// already in LittleEndian format.
fn should_swap_bytes(magic: u32) -> bool {
    matches!(magic, MH_CIGAM | MH_CIGAM_64 | FAT_CIGAM | FAT_CIGAM_64)
}

/// Convert a decimal number representation to a version string representation.
/// The decimal number is expected to be in the format
/// `major(rest of digits).minor(previous 2 digits).patch(last 2 digits)`.
///
/// # Arguments
///
/// * `decimal_number`: The decimal number to convert.
///
/// # Returns
///
/// A string representation of the version number.
fn convert_to_version_string(decimal_number: u32) -> String {
    let major = decimal_number >> 16;
    let minor = (decimal_number >> 8) & 0xFF;
    let patch = decimal_number & 0xFF;
    format!("{}.{}.{}", major, minor, patch)
}

/// Convert a decimal number representation to a source version string representation in a Mach-O.
/// The decimal number is expected to be in the format
/// `A.B.C.D.E packed as a24.b10.c10.d10.e10`.
///
/// # Arguments
///
/// * `decimal_number`: The decimal number to convert.
///
/// # Returns
///
/// A string representation of the version number.
fn convert_to_source_version_string(decimal_number: u64) -> String {
    let mask = 0x3f;
    let a = decimal_number >> 40;
    let b = (decimal_number >> 30) & mask;
    let c = (decimal_number >> 20) & mask;
    let d = (decimal_number >> 10) & mask;
    let e = decimal_number & mask;
    format!("{}.{}.{}.{}.{}", a, b, c, d, e)
}

/// Convert a Mach-O Relative Virtual Address (RVA) to an offset within the
/// file.
///
/// # Arguments
///
/// * `address`: The RVA to convert.
/// * `macho_file`: A reference to the Mach-O file.
///
/// # Returns
///
/// An `Option<u64>` which is `Some` if a corresponding offset is found,
/// otherwise `None`.
/// # Errors
///
/// * `MachoError::Overflow`: If integer overflow occurs during the
/// calculation.
fn macho_rva_to_offset(
    address: u64,
    macho_file: &File,
) -> Result<Option<u64>, MachoError> {
    for segment in &macho_file.segments {
        let (start, vmsize, fileoff) = (
            segment.vmaddr.ok_or(MachoError::Overflow)?,
            segment.vmsize.ok_or(MachoError::Overflow)?,
            segment.fileoff.ok_or(MachoError::Overflow)?,
        );

        let end = start.checked_add(vmsize).ok_or(MachoError::Overflow)?;

        if address >= start && address < end {
            let offset = fileoff
                .checked_add(
                    address.checked_sub(start).ok_or(MachoError::Overflow)?,
                )
                .ok_or(MachoError::Overflow)?;
            return Ok(Some(offset));
        }
    }

    Ok(None)
}

/// Convert a Mach-O file offset to a Relative Virtual Address (RVA).
///
/// # Arguments
///
/// * `offset`: The file offset to convert.
/// * `macho_file`: A reference to the Mach-O file.
///
/// # Returns
///
/// An `Option<u64>` which is `Some` if a corresponding RVA is found, otherwise
/// `None`.
///
/// # Errors
///
/// * `MachoError::Overflow`: If integer overflow occurs during the
/// calculation.
fn macho_offset_to_rva(
    offset: u64,
    macho_file: &File,
) -> Result<Option<u64>, MachoError> {
    for segment in &macho_file.segments {
        let (start, filesize, vmaddr) = (
            segment.fileoff.ok_or(MachoError::Overflow)?,
            segment.filesize.ok_or(MachoError::Overflow)?,
            segment.vmaddr.ok_or(MachoError::Overflow)?,
        );

        let end = start.checked_add(filesize).ok_or(MachoError::Overflow)?;

        if offset >= start && offset < end {
            let rva = vmaddr
                .checked_add(
                    offset.checked_sub(start).ok_or(MachoError::Overflow)?,
                )
                .ok_or(MachoError::Overflow)?;
            return Ok(Some(rva));
        }
    }

    Ok(None)
}

/// Swaps the endianness of fields within a 64-bit Mach-O header from BigEndian
/// to LittleEndian. This operation is performed in-place.
///
/// # Arguments
///
/// * `header`: A mutable reference to the 64-bit Mach-O header.
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

/// Swaps the endianness of fields within a Mach-O load command from BigEndian
/// to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O load command.
fn swap_load_command(command: &mut LoadCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O source version load command
/// from BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O load command.
fn swap_source_version_command(command: &mut SourceVersionCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.version = BigEndian::read_u64(&command.version.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O dylib from BigEndian
/// to LittleEndian in-place.
///
/// # Arguments
///
/// * `dylib`: A mutable reference to the Mach-O dylib.
fn swap_dylib(dylib: &mut DylibObject) {
    dylib.offset = BigEndian::read_u32(&dylib.offset.to_le_bytes());
    dylib.timestamp = BigEndian::read_u32(&dylib.timestamp.to_le_bytes());
    dylib.compatibility_version =
        BigEndian::read_u32(&dylib.compatibility_version.to_le_bytes());
    dylib.current_version =
        BigEndian::read_u32(&dylib.current_version.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O dylib command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O dylib command.
fn swap_dylib_command(command: &mut DylibCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O dyld info command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O dyld info command.
fn swap_dyld_info_command(command: &mut DyldInfoCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.rebase_off =
        BigEndian::read_u32(&command.rebase_off.to_le_bytes());
    command.rebase_size =
        BigEndian::read_u32(&command.rebase_size.to_le_bytes());
    command.bind_off = BigEndian::read_u32(&command.bind_off.to_le_bytes());
    command.bind_size = BigEndian::read_u32(&command.bind_size.to_le_bytes());
    command.weak_bind_off =
        BigEndian::read_u32(&command.weak_bind_off.to_le_bytes());
    command.weak_bind_size =
        BigEndian::read_u32(&command.weak_bind_size.to_le_bytes());
    command.lazy_bind_off =
        BigEndian::read_u32(&command.lazy_bind_off.to_le_bytes());
    command.lazy_bind_size =
        BigEndian::read_u32(&command.lazy_bind_size.to_le_bytes());
    command.export_off =
        BigEndian::read_u32(&command.export_off.to_le_bytes());
    command.export_size =
        BigEndian::read_u32(&command.export_size.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O dylinker command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O dylinker command.
fn swap_dylinker_command(command: &mut DylinkerCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.offset = BigEndian::read_u32(&command.offset.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O rpath command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O rpath command.
fn swap_rpath_command(command: &mut RPathCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.offset = BigEndian::read_u32(&command.offset.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O SymtabCommand command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O DysymtabCommand command.
fn swap_symtab_command(command: &mut SymtabCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.symoff = BigEndian::read_u32(&command.symoff.to_le_bytes());
    command.nsyms = BigEndian::read_u32(&command.nsyms.to_le_bytes());
    command.stroff = BigEndian::read_u32(&command.stroff.to_le_bytes());
    command.strsize = BigEndian::read_u32(&command.strsize.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O DysymtabCommand command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O DysymtabCommand command.
fn swap_dysymtab_command(command: &mut DysymtabCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.ilocalsym = BigEndian::read_u32(&command.ilocalsym.to_le_bytes());
    command.nlocalsym = BigEndian::read_u32(&command.nlocalsym.to_le_bytes());
    command.iextdefsym =
        BigEndian::read_u32(&command.iextdefsym.to_le_bytes());
    command.nextdefsym =
        BigEndian::read_u32(&command.nextdefsym.to_le_bytes());
    command.tocoff = BigEndian::read_u32(&command.tocoff.to_le_bytes());
    command.ntoc = BigEndian::read_u32(&command.ntoc.to_le_bytes());
    command.modtaboff = BigEndian::read_u32(&command.modtaboff.to_le_bytes());
    command.nmodtab = BigEndian::read_u32(&command.nmodtab.to_le_bytes());
    command.extrefsymoff =
        BigEndian::read_u32(&command.extrefsymoff.to_le_bytes());
    command.nextrefsyms =
        BigEndian::read_u32(&command.nextrefsyms.to_le_bytes());
    command.indirectsymoff =
        BigEndian::read_u32(&command.indirectsymoff.to_le_bytes());
    command.nindirectsyms =
        BigEndian::read_u32(&command.nindirectsyms.to_le_bytes());
    command.extreloff = BigEndian::read_u32(&command.extreloff.to_le_bytes());
    command.nextrel = BigEndian::read_u32(&command.nextrel.to_le_bytes());
    command.locreloff = BigEndian::read_u32(&command.locreloff.to_le_bytes());
    command.nlocrel = BigEndian::read_u32(&command.nlocrel.to_le_bytes());
}

/// Swaps the endianness of fields within a 32-bit Mach-O segment command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `segment`: A mutable reference to the 32-bit Mach-O segment command.
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

/// Swaps the endianness of fields within a 64-bit Mach-O segment command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `segment`: A mutable reference to the 64-bit Mach-O segment command.
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

/// Swaps the endianness of fields within a 32-bit Mach-O segment section from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `section`: A mutable reference to the 32-bit Mach-O segment section.
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

/// Swaps the endianness of fields within a 64-bit Mach-O segment section from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `section`: A mutable reference to the 64-bit Mach-O segment section.
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
    section.reserved3 = BigEndian::read_u32(&section.reserved3.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O entry point command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `section`: A mutable reference to the Mach-O entry point command section.
fn swap_entry_point_command(section: &mut EntryPointCommand) {
    section.cmd = BigEndian::read_u32(&section.cmd.to_le_bytes());
    section.cmdsize = BigEndian::read_u32(&section.cmdsize.to_le_bytes());
    section.entryoff = BigEndian::read_u64(&section.entryoff.to_le_bytes());
    section.stacksize = BigEndian::read_u64(&section.stacksize.to_le_bytes());
}

/// Parse the Mach-O 64-bit header. Capable of handling both 32-bit and 64-bit
/// formats.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw Mach-O header data.
///
/// # Returns
///
/// A `nom` IResult containing either the remaining input and the parsed
/// MachOHeader64 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse the FAT header of a Mach-O binary, providing a structured
/// representation.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw FAT header data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed FatHeader
/// structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_fat_header(input: &[u8]) -> IResult<&[u8], FatHeader> {
    let (input, magic) = be_u32(input)?;
    let (input, nfat_arch) = be_u32(input)?;
    Ok((input, FatHeader { magic, nfat_arch }))
}

/// Parse the 32-bit FAT architecture data, offering insights into the binary's
/// structure.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw 32-bit FAT architecture
///   data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed FatArch32
/// structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_fat_arch_32(input: &[u8]) -> IResult<&[u8], FatArch32> {
    let (input, cputype) = be_u32(input)?;
    let (input, cpusubtype) = be_u32(input)?;
    let (input, offset) = be_u32(input)?;
    let (input, size) = be_u32(input)?;
    let (input, align) = be_u32(input)?;

    Ok((input, FatArch32 { cputype, cpusubtype, offset, size, align }))
}

/// Parse the 64-bit FAT architecture data to understand the binary's layout
/// and characteristics.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw 64-bit FAT architecture
///   data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed FatArch64
/// structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse a Mach-O LoadCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw LoadCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// LoadCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_load_command(input: &[u8]) -> IResult<&[u8], LoadCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;

    Ok((input, LoadCommand { cmd, cmdsize }))
}

/// Parse a Mach-O SourceVersionCommand, transforming raw bytes into a
/// structured format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw SourceVersionCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// SourceVersionCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_source_version_command(
    input: &[u8],
) -> IResult<&[u8], SourceVersionCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, version) = le_u64(input)?;
    Ok((input, SourceVersionCommand { cmd, cmdsize, version }))
}

/// Parse a Mach-O Dylib object, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw dylib object data.
/// * `cmdsize`: the size of the load command data
/// * `swap`: indicator the endianness needs to be swapped
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// dylib structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_dylib(
    input: &[u8],
    cmdsize: u32,
    swap: bool,
) -> IResult<&[u8], DylibObject> {
    let (input, offset) = le_u32(input)?;
    let (input, timestamp) = le_u32(input)?;
    let (input, current_version) = le_u32(input)?;
    let (input, compatibility_version) = le_u32(input)?;

    let mut dy = DylibObject {
        offset,
        timestamp,
        current_version,
        compatibility_version,
        ..Default::default()
    };

    if swap {
        swap_dylib(&mut dy);
    }

    let (input, name) = take(cmdsize - dy.offset)(input)?;
    dy.name = name.into();

    Ok((input, dy))
}

/// Parse a Mach-O DylibCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw DylibCommand data.
/// * `swap`: indicator the endianness needs to be swapped
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// DylibCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_dylib_command(
    input: &[u8],
    swap: bool,
) -> IResult<&[u8], DylibCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;

    let mut dy = DylibCommand { cmd, cmdsize, ..Default::default() };

    if swap {
        swap_dylib_command(&mut dy);
    }

    let (input, dylib) = parse_dylib(input, dy.cmdsize, swap)?;
    dy.dylib = dylib;

    Ok((input, dy))
}

/// Parse a Mach-O DyldInfoCommand, transforming raw bytes into a
/// structured format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw DyldInfoCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// DyldInfoCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_dyld_info_command(input: &[u8]) -> IResult<&[u8], DyldInfoCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, rebase_off) = le_u32(input)?;
    let (input, rebase_size) = le_u32(input)?;
    let (input, bind_off) = le_u32(input)?;
    let (input, bind_size) = le_u32(input)?;
    let (input, weak_bind_off) = le_u32(input)?;
    let (input, weak_bind_size) = le_u32(input)?;
    let (input, lazy_bind_off) = le_u32(input)?;
    let (input, lazy_bind_size) = le_u32(input)?;
    let (input, export_off) = le_u32(input)?;
    let (input, export_size) = le_u32(input)?;

    Ok((
        input,
        DyldInfoCommand {
            cmd,
            cmdsize,
            rebase_off,
            rebase_size,
            bind_off,
            bind_size,
            weak_bind_off,
            weak_bind_size,
            lazy_bind_off,
            lazy_bind_size,
            export_off,
            export_size,
        },
    ))
}

/// Parse a Mach-O DylinkerCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw DylinkerCommand data.
/// * `swap`: indicator the endianness needs to be swapped
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// DylinkerCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_dylinker_command(
    input: &[u8],
    swap: bool,
) -> IResult<&[u8], DylinkerCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, offset) = le_u32(input)?;

    let mut dyl =
        DylinkerCommand { cmd, cmdsize, offset, ..Default::default() };

    if swap {
        swap_dylinker_command(&mut dyl);
    }

    let (input, name) = take(dyl.cmdsize - dyl.offset)(input)?;

    dyl.name = name.into();

    Ok((input, dyl))
}

/// Parse a Mach-O RPathCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw RPathCommand data.
/// * `swap`: indicator the endianness needs to be swapped
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// RPathCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_rpath_command(
    input: &[u8],
    swap: bool,
) -> IResult<&[u8], RPathCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, offset) = le_u32(input)?;

    let mut rp = RPathCommand { cmd, cmdsize, offset, ..Default::default() };

    if swap {
        swap_rpath_command(&mut rp);
    }

    let (input, path) = take(rp.cmdsize - rp.offset)(input)?;

    rp.path = path.into();

    Ok((input, rp))
}

/// Parse a Mach-O SymtabCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw SymtabCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// SymtabCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_symtab_command(input: &[u8]) -> IResult<&[u8], SymtabCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, symoff) = le_u32(input)?;
    let (input, nsyms) = le_u32(input)?;
    let (input, stroff) = le_u32(input)?;
    let (input, strsize) = le_u32(input)?;

    Ok((input, SymtabCommand { cmd, cmdsize, symoff, nsyms, stroff, strsize }))
}

/// Parse a Mach-O DysymtabCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw DysymtabCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// DysymtabCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_dysymtab_command(input: &[u8]) -> IResult<&[u8], DysymtabCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, ilocalsym) = le_u32(input)?;
    let (input, nlocalsym) = le_u32(input)?;
    let (input, iextdefsym) = le_u32(input)?;
    let (input, nextdefsym) = le_u32(input)?;
    let (input, tocoff) = le_u32(input)?;
    let (input, ntoc) = le_u32(input)?;
    let (input, modtaboff) = le_u32(input)?;
    let (input, nmodtab) = le_u32(input)?;
    let (input, extrefsymoff) = le_u32(input)?;
    let (input, nextrefsyms) = le_u32(input)?;
    let (input, indirectsymoff) = le_u32(input)?;
    let (input, nindirectsyms) = le_u32(input)?;
    let (input, extreloff) = le_u32(input)?;
    let (input, nextrel) = le_u32(input)?;
    let (input, locreloff) = le_u32(input)?;
    let (input, nlocrel) = le_u32(input)?;

    Ok((
        input,
        DysymtabCommand {
            cmd,
            cmdsize,
            ilocalsym,
            nlocalsym,
            iextdefsym,
            nextdefsym,
            tocoff,
            ntoc,
            modtaboff,
            nmodtab,
            extrefsymoff,
            nextrefsyms,
            indirectsymoff,
            nindirectsyms,
            extreloff,
            nextrel,
            locreloff,
            nlocrel,
        },
    ))
}

/// Parse the 32-bit segment command of a Mach-O file, offering a structured
/// view of its content.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw 32-bit segment command data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// SegmentCommand32 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse the 64-bit segment command, enabling a detailed examination of the
/// Mach-O file’s segments.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw 64-bit segment command data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// SegmentCommand64 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse a Mach-O 32-bit section, providing a detailed, structured format of
/// the section’s content.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw 32-bit section data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// SegmentSection32 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse a Mach-O 64-bit section, enabling a structured examination of the
/// content.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw 64-bit section data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// SegmentSection64 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse the Mach-O thread command, offering insights into the thread’s
/// attributes and states.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw thread command data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed ThreadCommand
/// structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_thread_command(input: &[u8]) -> IResult<&[u8], ThreadCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, flavor) = le_u32(input)?;
    let (input, count) = le_u32(input)?;

    Ok((input, ThreadCommand { cmd, cmdsize, flavor, count }))
}

/// Parse the Mach-O entry point command, providing a structured representation
/// of the data.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw entry point command data.
///
/// # Returns
///
/// A `nom` IResult containing either the remaining input and the parsed
/// EntryPointCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_entry_point_command(
    input: &[u8],
) -> IResult<&[u8], EntryPointCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, entryoff) = le_u64(input)?;
    let (input, stacksize) = le_u64(input)?;

    Ok((input, EntryPointCommand { cmd, cmdsize, entryoff, stacksize }))
}

/// Parse the X86 thread state data, offering insights into the CPU's state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw X86 thread state data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// X86ThreadState structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse the ARM thread state data, providing detailed information on the
/// CPU’s current state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw ARM thread state data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// ARMThreadState structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_arm_thread_state(input: &[u8]) -> IResult<&[u8], ARMThreadState> {
    let (input, r) = count(le_u32, 13)(input)?;
    let (input, sp) = le_u32(input)?;
    let (input, lr) = le_u32(input)?;
    let (input, pc) = le_u32(input)?;
    let (input, cpsr) = le_u32(input)?;

    Ok((input, ARMThreadState { r, sp, lr, pc, cpsr }))
}

/// Parse the PPC thread state data to retrieve detailed information about the
/// PowerPC CPU's state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw PPC thread state data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// PPCThreadState structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse the SPARC thread state, providing insights into the SPARC CPU’s
/// state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw SPARC thread state data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// SPARCThreadState structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_sparc_thread_state(input: &[u8]) -> IResult<&[u8], SPARCThreadState> {
    let (input, psr) = le_u32(input)?;
    let (input, pc) = le_u32(input)?;
    let (input, npc) = le_u32(input)?;
    let (input, y) = le_u32(input)?;
    let (input, g) = count(le_u32, 7)(input)?;
    let (input, o) = count(le_u32, 7)(input)?;

    Ok((input, SPARCThreadState { psr, pc, npc, y, g, o }))
}

/// Parse the M68K thread state, offering a detailed, structured view of the
/// CPU's state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw M68K thread state data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// M68KThreadState structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_m68k_thread_state(input: &[u8]) -> IResult<&[u8], M68KThreadState> {
    let (input, dreg) = count(le_u32, 8)(input)?;
    let (input, areg) = count(le_u32, 8)(input)?;
    let (input, pad) = le_u16(input)?;
    let (input, sr) = le_u16(input)?;
    let (input, pc) = le_u32(input)?;

    Ok((input, M68KThreadState { dreg, areg, pad, sr, pc }))
}

/// Parse the M88K thread state, enabling detailed insights into the CPU’s
/// current state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw M88K thread state data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// M88KThreadState structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_m88k_thread_state(input: &[u8]) -> IResult<&[u8], M88KThreadState> {
    let (input, r) = count(le_u32, 31)(input)?;
    let (input, xip) = le_u32(input)?;
    let (input, xip_in_bd) = le_u32(input)?;
    let (input, nip) = le_u32(input)?;

    Ok((input, M88KThreadState { r, xip, xip_in_bd, nip }))
}

/// Parse the X86 64-bit thread state data to offer a comprehensive view of the
/// CPU’s state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw X86 64-bit thread state
///   data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// X86ThreadState64 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse the ARM 64-bit thread state, offering a detailed, structured format
/// for the CPU’s state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw ARM 64-bit thread state
///   data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// ARMThreadState64 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_arm_thread_state64(input: &[u8]) -> IResult<&[u8], ARMThreadState64> {
    let (input, r) = count(le_u64, 29)(input)?;
    let (input, fp) = le_u64(input)?;
    let (input, lr) = le_u64(input)?;
    let (input, sp) = le_u64(input)?;
    let (input, pc) = le_u64(input)?;
    let (input, cpsr) = le_u32(input)?;

    Ok((input, ARMThreadState64 { r, fp, lr, sp, pc, cpsr }))
}

/// Parse the PPC 64-bit thread state to retrieve detailed information about
/// the PowerPC CPU's state.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw PPC 64-bit thread state
///   data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// PPCThreadState64 structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Handles the LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB, and
/// LC_REEXPORT_DYLIB commands for Mach-O files, parsing the data
/// and populating a protobuf representation of the dylib.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the dylib command.
/// * `size`: The size of the dylib command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected DylibCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   dylib command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_dylib_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // 24 bytes for all integer fields and offset in Dylib/DylibCommand
    // fat pointer of vec makes for inaccurate count
    if size < 24 {
        return Err(MachoError::FileSectionTooSmall(
            "DylibCommand".to_string(),
        ));
    }

    let swap = should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    );

    let (_, dy) = parse_dylib_command(command_data, swap)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    let dylib = Dylib {
        name: Some(
            std::str::from_utf8(&dy.dylib.name)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .to_string(),
        ),
        timestamp: Some(dy.dylib.timestamp),
        compatibility_version: Some(convert_to_version_string(
            dy.dylib.compatibility_version,
        )),
        current_version: Some(convert_to_version_string(
            dy.dylib.current_version,
        )),
        ..Default::default()
    };

    macho_file.dylibs.push(dylib);

    Ok(())
}

/// Handles the LC_DYLD_INFO_ONLY and LC_DYLD_INFO commands for Mach-O files,
/// parsing the data and populating a protobuf representation of the dyld info command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the dyld info command.
/// * `size`: The size of the dyld info command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected DyldInfoCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   dyld info command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_dyld_info_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<DyldInfoCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "DyldInfoCommand".to_string(),
        ));
    }

    let (_, mut dyl) = parse_dyld_info_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_dyld_info_command(&mut dyl);
    };

    macho_file.dyld_info = MessageField::some(DyldInfo {
        cmd: Some(dyl.cmd),
        cmdsize: Some(dyl.cmdsize),
        rebase_off: Some(dyl.rebase_off),
        rebase_size: Some(dyl.rebase_size),
        bind_off: Some(dyl.bind_off),
        bind_size: Some(dyl.bind_size),
        weak_bind_off: Some(dyl.weak_bind_off),
        weak_bind_size: Some(dyl.weak_bind_size),
        lazy_bind_off: Some(dyl.lazy_bind_off),
        lazy_bind_size: Some(dyl.lazy_bind_size),
        export_off: Some(dyl.export_off),
        export_size: Some(dyl.export_size),
        ..Default::default()
    });

    Ok(())
}
/// Handles the LC_ID_DYLINKER, LC_LOAD_DYLINKER and LC_DYLD_ENVIRONMENT
/// commands for Mach-O files, parsing the data and populating a protobuf
/// representation of the rpath command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the rpath command.
/// * `size`: The size of the Dylinker command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected DylinkerCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   dylinker command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_dylinker_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // 4 bytes for cmd, 4 bytes for cmdsize, 4 bytes for offset
    // fat pointer of vec makes for inaccurate count
    if size < 12 {
        return Err(MachoError::FileSectionTooSmall(
            "DylinkerCommand".to_string(),
        ));
    }

    let swap = should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    );

    let (_, dyl) = parse_dylinker_command(command_data, swap)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    macho_file.dynamic_linker = Some(
        std::str::from_utf8(&dyl.name)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .to_string(),
    );

    Ok(())
}

/// Handles the LC_ID_DYLINKER, LC_LOAD_DYLINKER and LC_DYLD_ENVIRONMENT
/// commands for Mach-O files, parsing the data and populating a protobuf
/// representation of the rpath command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the SourceVersion command.
/// * `size`: The size of the SourceVersion command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected SourceVersion struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   SourceVersion data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_source_version_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<SourceVersionCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "SourceVersion".to_string(),
        ));
    }

    let (_, mut sv) = parse_source_version_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_source_version_command(&mut sv);
    };

    macho_file.source_version =
        Some(convert_to_source_version_string(sv.version));

    Ok(())
}

/// Handles the LC_RPATH commands for Mach-O files, parsing the data
/// and populating a protobuf representation of the rpath command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the rpath command.
/// * `size`: The size of the rpath command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected RPathCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   rpath command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_rpath_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // 4 bytes for cmd, 4 bytes for cmdsize, 4 bytes for offset
    // fat pointer of vec makes for inaccurate count
    if size < 12 {
        return Err(MachoError::FileSectionTooSmall(
            "RPathCommand".to_string(),
        ));
    }

    let swap = should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    );

    let (_, rp) = parse_rpath_command(command_data, swap)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    let rpath = RPath {
        cmd: Some(rp.cmd),
        cmdsize: Some(rp.cmdsize),
        path: Some(
            std::str::from_utf8(&rp.path)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .to_string(),
        ),
        ..Default::default()
    };

    macho_file.rpaths.push(rpath);
    Ok(())
}

/// Handles the LC_SYMTAB command for Mach-O files, parsing the data
/// and populating a protobuf representation of the symtab command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the symtab command.
/// * `size`: The size of the symtab command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected SymtabCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   symtab command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_symtab_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<SymtabCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "SymtabCommand".to_string(),
        ));
    }

    let (_, mut sym) = parse_symtab_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_symtab_command(&mut sym);
    };

    macho_file.symtab = MessageField::some(Symtab {
        cmd: Some(sym.cmd),
        cmdsize: Some(sym.cmdsize),
        symoff: Some(sym.symoff),
        nsyms: Some(sym.nsyms),
        stroff: Some(sym.stroff),
        strsize: Some(sym.strsize),
        ..Default::default()
    });

    Ok(())
}

/// Handles the LC_DYSYMTAB command for Mach-O files, parsing the data
/// and populating a protobuf representation of the dysymtab command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the dysymtab command.
/// * `size`: The size of the dysymtab command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected SymtabCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   dysymtab command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_dysymtab_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<DysymtabCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "DysymtabCommand".to_string(),
        ));
    }

    let (_, mut dysym) = parse_dysymtab_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_dysymtab_command(&mut dysym);
    };

    macho_file.dysymtab = MessageField::some(Dysymtab {
        cmd: Some(dysym.cmd),
        cmdsize: Some(dysym.cmdsize),
        ilocalsym: Some(dysym.ilocalsym),
        nlocalsym: Some(dysym.nlocalsym),
        iextdefsym: Some(dysym.iextdefsym),
        nextdefsym: Some(dysym.nextdefsym),
        tocoff: Some(dysym.tocoff),
        ntoc: Some(dysym.ntoc),
        modtaboff: Some(dysym.modtaboff),
        nmodtab: Some(dysym.nmodtab),
        extrefsymoff: Some(dysym.extrefsymoff),
        nextrefsyms: Some(dysym.nextrefsyms),
        indirectsymoff: Some(dysym.indirectsymoff),
        nindirectsyms: Some(dysym.nindirectsyms),
        extreloff: Some(dysym.extreloff),
        nextrel: Some(dysym.nextrel),
        locreloff: Some(dysym.locreloff),
        nlocrel: Some(dysym.nlocrel),
        ..Default::default()
    });

    Ok(())
}
/// Handles the LC_SEGMENT command for 32-bit Mach-O files, parsing the data
/// and populating a protobuf representation of the segment and its associated
/// file sections.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the segment command.
/// * `size`: The size of the segment command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected SegmentCommand32 struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   segment command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
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
            std::str::from_utf8(&sg.segname)
                .unwrap_or_default()
                .replace('\0', ""),
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
                    .replace('\0', ""),
            ),
            sectname: Some(
                std::str::from_utf8(&sec.sectname)
                    .unwrap_or_default()
                    .replace('\0', ""),
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

/// Handles the LC_SEGMENT_64 command for 64-bit Mach-O files, processing the
/// segment command data and populating a protobuf representation of the
/// segment and associated file sections.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the segment command.
/// * `size`: The size of the segment command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected SegmentCommand64 struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   segment command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
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
            std::str::from_utf8(&sg.segname)
                .unwrap_or_default()
                .replace('\0', ""),
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
                    .replace('\0', ""),
            ),
            sectname: Some(
                std::str::from_utf8(&sec.sectname)
                    .unwrap_or_default()
                    .replace('\0', ""),
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

/// Processes the `LC_UNIXTHREAD` command for older CPUs in Mach-O files,
/// extracting the entry point for various older CPU architectures. This
/// command is primarily used in older Mach-O file formats and has been
/// replaced by the `LC_MAIN` command in newer versions.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the UNIX thread command.
/// * `size`: The size of the UNIX thread command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: If the provided size is smaller than
///   the `ThreadCommand` struct.
/// * `MachoError::ParsingError`: Encountered when there's an error parsing the
///   UNIX thread command data.
/// * `MachoError::MissingHeaderValue`: Thrown if "cputype" or "magic" header
///   values are missing.
/// * `MachoError::Overflow`: If there is an overflow during command size
///   computation.
/// * `MachoError::UnsupportedCPUType`: If the CPU type is not supported.
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

    let thread_state_size = command_size
        .checked_sub(std::mem::size_of::<ThreadCommand>())
        .ok_or(MachoError::Overflow)?;
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

    // Swap bytes if necessary
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
    macho_file.entry_point = macho_rva_to_offset(address, macho_file)?;

    Ok(())
}

/// Processes the `LC_MAIN` command for Mach-O files, extracting the entry
/// point for the Mach-O file and setting its stack size.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the main command.
/// * `size`: The size of the main command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: If the provided size is smaller than
///   the `EntryPointCommand` struct.
/// * `MachoError::ParsingError`: Encountered when there's an error parsing the
///   main command data.
/// * `MachoError::MissingHeaderValue`: Thrown if the "magic" header value is
///   missing, needed to decide if bytes should be swapped.
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

    // Swap bytes if necessary
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
            macho_offset_to_rva(entrypoint_cmd.entryoff, macho_file)?;
    } else {
        macho_file.set_entry_point(entrypoint_cmd.entryoff);
    }

    macho_file.set_stack_size(entrypoint_cmd.stacksize);

    Ok(())
}

/// Processes individual command segments based on their load command type.
///
/// This function is designed to manage various command segments present in
/// Mach-O files, depending on the given load command type. It is equipped to
/// handle both 32-bit and 64-bit Mach-O files and processes commands like
/// `LC_UNIXTHREAD` and `LC_MAIN`.
///
/// # Arguments
///
/// * `cmd`: The type of the load command.
/// * `cmdsize`: The size of the command data.
/// * `command_data`: The raw byte data of the command.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
/// * `process_segments`: Flag that decides if segment commands should be
///   processed.
///
/// # Returns
///
/// Returns a `Result<u64, MachoError>` indicating either the number of
/// segments processed successfully, or an error encountered during the
/// operation.
///
/// # Errors
///
/// The function can propagate errors from `handle_segment_command`,
/// `handle_segment_command_64`, `handle_unixthread`, and `handle_main`
/// functions.
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
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB
            | LC_REEXPORT_DYLIB => {
                handle_dylib_command(command_data, cmdsize, macho_file)?;
            }
            LC_RPATH => {
                handle_rpath_command(command_data, cmdsize, macho_file)?;
            }
            LC_ID_DYLINKER | LC_LOAD_DYLINKER | LC_DYLD_ENVIRONMENT => {
                handle_dylinker_command(command_data, cmdsize, macho_file)?;
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                handle_dyld_info_command(command_data, cmdsize, macho_file)?;
            }
            LC_SOURCE_VERSION => {
                handle_source_version_command(
                    command_data,
                    cmdsize,
                    macho_file,
                )?;
            }
            LC_SYMTAB => {
                handle_symtab_command(command_data, cmdsize, macho_file)?;
            }
            LC_DYSYMTAB => {
                handle_dysymtab_command(command_data, cmdsize, macho_file)?;
            }
            _ => {}
        }
    }

    Ok(seg_count)
}

/// Processes the symbol table and string table based on the values calculated
/// from the LC_SYMTAB load command.
///
/// # Arguments
///
/// * `data`: The raw byte data of the Mach-O file.
/// * `macho_file`: The protobuf representation of the Mach-O file to be populated.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// parsing operation.
fn parse_macho_symtab_tables(
    data: &[u8],
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if macho_file.symtab.is_some() {
        let symtab = macho_file.symtab.as_mut().unwrap();

        let str_offset = symtab.stroff() as usize;
        let str_end = symtab.strsize() as usize;
        // We don't want the dyld_shared_cache ones for now
        if str_offset < data.len() {
            let string_table: &[u8] = &data[str_offset..str_offset + str_end];
            let strings: Vec<String> = string_table
                .split(|&c| c == b'\0')
                .map(|line| {
                    std::str::from_utf8(line)
                        .unwrap_or_default()
                        .trim_end_matches('\0')
                        .to_string()
                })
                .filter(|s| !s.trim().is_empty())
                .collect();

            symtab.strings = strings;
        }
    }

    Ok(())
}

/// Parses the Mach-O command data from the binary and populates the provided
/// protobuf representation.
///
/// This function works by looping through Mach-O commands, parsing each and
/// updating the `macho_file` protobuf representation accordingly.
///
/// # Arguments
///
/// * `data`: The raw byte data of the Mach-O file.
/// * `macho_file`: The protobuf representation of the Mach-O file to be
///   populated.
/// * `process_segments`: A flag that decides if segments should be processed.
///
/// # Returns
///
/// Returns a `Result<u64, MachoError>` indicating either the number of
/// segments successfully parsed, or an error if the operation fails.
///
/// # Errors
///
/// * `MachoError::MissingHeaderValue`: Occurs if essential header values like
///   "magic" or "ncmds" are missing.
/// * `MachoError::Overflow`: Arises if there's an arithmetic overflow during
///   command offset computation or remaining data size calculation.
/// * `MachoError::ParsingError`: Captures any error encountered during the
///   parsing of load commands from the Mach-O file.
///
/// The function also propagates errors from the `handle_command` function.
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
        let remaining_data_size = data
            .len()
            .checked_sub(command_offset)
            .ok_or(MachoError::Overflow)?;
        if remaining_data_size < std::mem::size_of::<LoadCommand>() {
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
        let remaining_data_size = data
            .len()
            .checked_sub(command_offset)
            .ok_or(MachoError::Overflow)?;
        if remaining_data_size < command.cmdsize as usize {
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

/// Parses a basic Mach-O file and populates a protobuf representation.
///
/// The function reads the raw data of the Mach-O file, checks if it's a valid
/// Mach-O file by inspecting the header, and then processes all the commands
/// contained within it. It fills a protobuf `File` object with the extracted
/// information.
///
/// # Arguments
///
/// * `data`: The raw byte data of the Mach-O file.
///
/// # Returns
///
/// Returns a `Result<File, MachoError>` either with a populated Mach-O
/// protobuf representation or an error if the parsing operation fails.
///
/// # Errors
///
/// * `MachoError::FileTooSmall`: This error is thrown if the provided data is
///   too small to contain a Mach-O header.
/// * `MachoError::ParsingError`: This error occurs when there's a problem
///   parsing the Mach-O header.
///
/// It also propagates errors from `parse_macho_commands`.
#[doc(hidden)]
pub fn parse_macho_file(data: &[u8]) -> Result<File, MachoError> {
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

    // Populate symbol table
    parse_macho_symtab_tables(data, &mut macho_file)?;

    Ok(macho_file)
}

/// Parses a FAT Mach-O file and updates the provided protobuf representation.
///
/// A FAT Mach-O file contains binary images for multiple supported
/// architectures. This function processes the FAT header and each of the
/// nested binary images, populating the provided protobuf representation
/// accordingly.
///
/// # Arguments
///
/// * `data`: The raw byte data of the FAT Mach-O file.
/// * `macho_proto`: The protobuf representation of the Mach-O file to be
///   populated.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// parsing operation.
///
/// # Errors
///
/// * `MachoError::ParsingError`: Occurs if there is an issue parsing the FAT
///   header or the architecture data.
/// * `MachoError::Overflow`: This error is raised if the offset index or the
///   end index goes beyond the size of the data array.
///
/// It also propagates errors from `parse_macho_file`.
#[doc(hidden)]
pub fn parse_fat_macho_file(
    data: &[u8],
    macho_proto: &mut Macho,
) -> Result<(), MachoError> {
    let (remaining_data, header) = parse_fat_header(data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    macho_proto.set_fat_magic(header.magic);
    macho_proto.set_nfat_arch(header.nfat_arch);

    // Depending on the size of the data, determine if it's a 32bit or 64bit
    // Mach-O
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

            // Return Overflow error in case offset index or end index is
            // bigger then data size
            let end_index =
                arch.offset
                    .checked_add(arch.size)
                    .ok_or(MachoError::Overflow)? as usize;

            if arch.offset as usize > data.len() || end_index > data.len() {
                return Err(MachoError::Overflow);
            }

            // Parse nested data as basic Mach-O file
            let nested_file =
                parse_macho_file(&data[arch.offset as usize..end_index])?;
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

            // Return Overflow error in case offset index or end index is
            // bigger then data size
            let end_index =
                arch.offset
                    .checked_add(arch.size)
                    .ok_or(MachoError::Overflow)? as usize;

            if arch.offset as usize > data.len() || end_index > data.len() {
                return Err(MachoError::Overflow);
            }

            // Parse nested data as basic Mach-O file
            let nested_file =
                parse_macho_file(&data[arch.offset as usize..end_index])?;
            macho_proto.file.push(nested_file);
        }
    }

    Ok(())
}

/// Get the index of a Mach-O file within a fat binary based on CPU type.
///
/// This function iterates through the architecture types contained in a
/// Mach-O fat binary and returns the index of the file that matches the
/// specified CPU type.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type to search for within the fat binary.
///
/// # Returns
///
/// An `Option<i64>` containing the index of the matching Mach-O file, or
/// `None` if no match is found.
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

/// Get the index of a Mach-O file within a fat binary based on both
/// CPU type and subtype.
///
/// This function extends `file_index_type` by also considering the CPU subtype
/// during the search, allowing for more precise matching.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type to search for.
/// * `subtype_arg`: The CPU subtype to search for.
///
/// # Returns
///
/// An `Option<i64>` containing the index of the matching Mach-O file, or
/// `None` if no match is found.
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

/// Get the real entry point offset for a specific CPU type within a fat
/// Mach-O binary.
///
/// It navigates through the architectures in the binary, finds the one that
/// matches the specified CPU type, and returns its entry point offset.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type of the desired architecture.
///
/// # Returns
///
/// An `Option<i64>` containing the offset of the entry point for the specified
/// architecture, or `None` if not found.
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
                    return file_offset
                        .checked_add(entry_point)
                        .map(|sum| sum as i64);
                }
            }
        }
    }

    None
}

/// Get the real entry point offset for a specific CPU type and subtype
/// within a fat Mach-O binary.
///
/// Similar to `ep_for_arch_type`, but adds consideration for the CPU subtype
/// to allow for more precise location of the entry point.
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `type_arg`: The CPU type of the desired architecture.
/// * `subtype_arg`: The CPU subtype of the desired architecture.
///
/// # Returns
///
/// An `Option<i64>` containing the offset of the entry point for the specified
/// architecture and subtype, or `None` if not found.
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
                    return file_offset
                        .checked_add(entry_point)
                        .map(|sum| sum as i64);
                }
            }
        }
    }

    None
}

/// The function for checking if any dylib name present in the main Mach-O or embedded Mach-O files
/// contain a dylib with the desired name
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `dylib_name`: The name of the dylib to check if present
///
/// # Returns
///
/// An `Option<bool>` containing if the name is found
#[module_export(name = "dylib_present")]
fn dylibs_present(
    ctx: &ScanContext,
    dylib_name: RuntimeString,
) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected_name = dylib_name.as_bstr(ctx);

    for dylib in macho.dylibs.iter() {
        if dylib.name.as_ref().is_some_and(|name| {
            expected_name.eq_ignore_ascii_case(name.as_bytes())
        }) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for dylib in file.dylibs.iter() {
            if dylib.name.as_ref().is_some_and(|name| {
                expected_name.eq_ignore_ascii_case(name.as_bytes())
            }) {
                return Some(true);
            }
        }
    }

    Some(false)
}

/// The function for checking if any rpath present in the main Mach-O or embedded Mach-O files
/// contain an rpath with the desired path
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `rpath`: The name of the rpath to check if present
///
/// # Returns
///
/// An `Option<bool>` containing if the path is found
#[module_export(name = "rpath_present")]
fn rpaths_present(ctx: &ScanContext, rpath: RuntimeString) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected_rpath = rpath.as_bstr(ctx);

    for rp in macho.rpaths.iter() {
        if rp.path.as_ref().is_some_and(|path| {
            expected_rpath.eq_ignore_ascii_case(path.as_bytes())
        }) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for rp in file.rpaths.iter() {
            if rp.path.as_ref().is_some_and(|path| {
                expected_rpath.eq_ignore_ascii_case(path.as_bytes())
            }) {
                return Some(true);
            }
        }
    }

    Some(false)
}

/// The primary function for processing a Mach-O file, extracting its
/// information and populating a `Macho` protobuf object with the extracted
/// data.
///
/// This function is designed to fail silently and return an empty or partially
/// filled protobuf in case of an error during the parsing process. More
/// detailed error information can be obtained with logging enabled.
///
/// # Arguments
///
/// * `ctx`: A reference to the scanning context.
///
/// # Returns
///
/// A `Macho` object populated with extracted data from the scanned Mach-O
/// file, or partially filled/empty in case of parsing errors.
///
/// # Error Handling
///
/// The function logs errors rather than propagating them, ensuring the calling
/// code isn’t interrupted by issues with individual files during bulk
/// processing.
#[module_main]
fn main(data: &[u8]) -> Macho {
    // Create an empty instance of the Mach-O protobuf
    let mut macho_proto = Macho::new();

    // If data is too short to be valid Mach-O file, return empty protobuf
    if data.len() < VALID_MACHO_LENGTH {
        #[cfg(feature = "logging")]
        error!("{}", MachoError::FileTooSmall);
        return macho_proto;
    }

    // Parse basic Mach-O file
    if is_macho_file_block(data) {
        match parse_macho_file(data) {
            // Parsing was successful, populate basic fields from parsed Mach-O
            // structure
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
                macho_proto.dylibs = file_data.dylibs;
                macho_proto.rpaths = file_data.rpaths;
                macho_proto.symtab = file_data.symtab;
                macho_proto.source_version = file_data.source_version;
                macho_proto.dynamic_linker = file_data.dynamic_linker;
                macho_proto.dyld_info = file_data.dyld_info;
                macho_proto.dysymtab = file_data.dysymtab;
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

    macho_proto
}
