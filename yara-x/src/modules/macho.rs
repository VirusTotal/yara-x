use crate::modules::prelude::*;
use crate::modules::protos::macho::*;

use arrayref::array_ref;
use byteorder::{BigEndian, ByteOrder};
use nom::{bytes::complete::take, multi::count, number::complete::*, IResult};

// Mach-O file needs to have at least header of size 28 to be considered correct
// Real minimum size of Mach-O file would be higher
const VALID_MACHO_LENGTH: usize = 28;

// Define Mach-O header constats
// May be moved away later
const MH_MAGIC: u32 = 0xFEEDFACE;
const MH_CIGAM: u32 = 0xCEFAEDFE;
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;

// Define Mach-O FAT header constants
const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_CIGAM: u32 = 0xBEBAFECA;
const FAT_MAGIC_64: u32 = 0xCAFEBABF;
const FAT_CIGAM_64: u32 = 0xBFBAFECA;

// Define Mach-O 64-bit masks
const CPU_ARCH_ABI64: u32 = 0x01000000;
const CPU_SUBTYPE_LIB64: u32 = 0x80000000;

// Define Mach-O CPU types
const CPU_TYPE_MC680X0: u32 = 0x00000006; // Motorola 68000
const CPU_TYPE_X86: u32 = 0x00000007; // AMD/Intel x86
const CPU_TYPE_X86_64: u32 = 0x01000007; // AMD/Intel x86-64
const CPU_TYPE_MIPS: u32 = 0x00000008; // MIPS
const CPU_TYPE_MC98000: u32 = 0x0000000a; // Motorola PowerPC
const CPU_TYPE_ARM: u32 = 0x0000000c; // ARM
const CPU_TYPE_ARM64: u32 = 0x0100000c; // ARM 64-bit
const CPU_TYPE_MC88000: u32 = 0x0000000d; // Motorola 88000
const CPU_TYPE_SPARC: u32 = 0x0000000e; // SPARC
const CPU_TYPE_POWERPC: u32 = 0x00000012; // PowerPC
const CPU_TYPE_POWERPC64: u32 = 0x01000012; // PowerPC 64-bit

// Define Mach-O INTEL CPU subtypes
const CPU_SUBTYPE_INTEL_MODEL_ALL: u32 = 0x00000000;
const CPU_SUBTYPE_386: u32 = 0x00000003;
const CPU_SUBTYPE_486: u32 = 0x00000004;
const CPU_SUBTYPE_486SX: u32 = 0x00000084;
const CPU_SUBTYPE_586: u32 = 0x00000005;
const CPU_SUBTYPE_PENT: u32 = 0x00000005;
const CPU_SUBTYPE_PENTPRO: u32 = 0x00000016;
const CPU_SUBTYPE_PENTII_M3: u32 = 0x00000036;
const CPU_SUBTYPE_PENTII_M5: u32 = 0x00000056;
const CPU_SUBTYPE_CELERON: u32 = 0x00000067;
const CPU_SUBTYPE_CELERON_MOBILE: u32 = 0x00000077;
const CPU_SUBTYPE_PENTIUM_3: u32 = 0x00000008;
const CPU_SUBTYPE_PENTIUM_3_M: u32 = 0x00000018;
const CPU_SUBTYPE_PENTIUM_3_XEON: u32 = 0x00000028;
const CPU_SUBTYPE_PENTIUM_M: u32 = 0x00000009;
const CPU_SUBTYPE_PENTIUM_4: u32 = 0x0000000a;
const CPU_SUBTYPE_PENTIUM_4_M: u32 = 0x0000001a;
const CPU_SUBTYPE_ITANIUM: u32 = 0x0000000b;
const CPU_SUBTYPE_ITANIUM_2: u32 = 0x0000001b;
const CPU_SUBTYPE_XEON: u32 = 0x0000000c;
const CPU_SUBTYPE_XEON_MP: u32 = 0x0000001c;

// Define Mach-O ARM CPU subtypes
const CPU_SUBTYPE_ARM_ALL: u32 = 0x00000000;
const CPU_SUBTYPE_ARM_V4T: u32 = 0x00000005;
const CPU_SUBTYPE_ARM_V6: u32 = 0x00000006;
const CPU_SUBTYPE_ARM_V5: u32 = 0x00000007;
const CPU_SUBTYPE_ARM_V5TEJ: u32 = 0x00000007;
const CPU_SUBTYPE_ARM_XSCALE: u32 = 0x00000008;
const CPU_SUBTYPE_ARM_V7: u32 = 0x00000009;
const CPU_SUBTYPE_ARM_V7F: u32 = 0x0000000a;
const CPU_SUBTYPE_ARM_V7S: u32 = 0x0000000b;
const CPU_SUBTYPE_ARM_V7K: u32 = 0x0000000c;
const CPU_SUBTYPE_ARM_V6M: u32 = 0x0000000e;
const CPU_SUBTYPE_ARM_V7M: u32 = 0x0000000f;
const CPU_SUBTYPE_ARM_V7EM: u32 = 0x00000010;

// Define Mach-O ARM64 CPU subtypes
const CPU_SUBTYPE_ARM64_ALL: u32 = 0x00000000;

// Define Mach-O SPARC CPU subtypes
const CPU_SUBTYPE_SPARC_ALL: u32 = 0x00000000;

// Define Mach-O PowerPC CPU subtypes
const CPU_SUBTYPE_POWERPC_ALL: u32 = 0x00000000;
const CPU_SUBTYPE_MC980000_ALL: u32 = 0x00000000;
const CPU_SUBTYPE_POWERPC_601: u32 = 0x00000001;
const CPU_SUBTYPE_MC98601: u32 = 0x00000001;
const CPU_SUBTYPE_POWERPC_602: u32 = 0x00000002;
const CPU_SUBTYPE_POWERPC_603: u32 = 0x00000003;
const CPU_SUBTYPE_POWERPC_603E: u32 = 0x00000004;
const CPU_SUBTYPE_POWERPC_603EV: u32 = 0x00000005;
const CPU_SUBTYPE_POWERPC_604: u32 = 0x00000006;
const CPU_SUBTYPE_POWERPC_604E: u32 = 0x00000007;
const CPU_SUBTYPE_POWERPC_620: u32 = 0x00000008;
const CPU_SUBTYPE_POWERPC_750: u32 = 0x00000009;
const CPU_SUBTYPE_POWERPC_7400: u32 = 0x0000000a;
const CPU_SUBTYPE_POWERPC_7450: u32 = 0x0000000b;
const CPU_SUBTYPE_POWERPC_970: u32 = 0x00000064;

// Define Mach-O file types
const MH_OBJECT: u32 = 0x00000001;
const MH_EXECUTE: u32 = 0x00000002;
const MH_FVMLIB: u32 = 0x00000003;
const MH_CORE: u32 = 0x00000004;
const MH_PRELOAD: u32 = 0x00000005;
const MH_DYLIB: u32 = 0x00000006;
const MH_DYLINKER: u32 = 0x00000007;
const MH_BUNDLE: u32 = 0x00000008;
const MH_DYLIB_STUB: u32 = 0x00000009;
const MH_DSYM: u32 = 0x0000000a;
const MH_KEXT_BUNDLE: u32 = 0x0000000b;

// Define Mach-O file flags
const MH_NOUNDEFS: u32 = 0x00000001;
const MH_INCRLINK: u32 = 0x00000002;
const MH_DYLDLINK: u32 = 0x00000004;
const MH_BINDATLOAD: u32 = 0x00000008;
const MH_PREBOUND: u32 = 0x00000010;
const MH_SPLIT_SEGS: u32 = 0x00000020;
const MH_LAZY_INIT: u32 = 0x00000040;
const MH_TWOLEVEL: u32 = 0x00000080;
const MH_FORCE_FLAT: u32 = 0x00000100;
const MH_NOMULTIDEFS: u32 = 0x00000200;
const MH_NOFIXPREBINDING: u32 = 0x00000400;
const MH_PREBINDABLE: u32 = 0x00000800;
const MH_ALLMODSBOUND: u32 = 0x00001000;
const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x00002000;
const MH_CANONICAL: u32 = 0x00004000;
const MH_WEAK_DEFINES: u32 = 0x00008000;
const MH_BINDS_TO_WEAK: u32 = 0x00010000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x00020000;
const MH_ROOT_SAFE: u32 = 0x00040000;
const MH_SETUID_SAFE: u32 = 0x00080000;
const MH_NO_REEXPORTED_DYLIBS: u32 = 0x00100000;
const MH_PIE: u32 = 0x00200000;
const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x00400000;
const MH_HAS_TLV_DESCRIPTORS: u32 = 0x00800000;
const MH_NO_HEAP_EXECUTION: u32 = 0x01000000;
const MH_APP_EXTENSION_SAFE: u32 = 0x02000000;

// Define Mach-O load commands
const LC_SEGMENT: u32 = 0x00000001;
const LC_UNIXTHREAD: u32 = 0x00000005;
const LC_SEGMENT_64: u32 = 0x00000019;
const LC_MAIN: u32 = 0x80000028;

// Define segment flags
const SG_HIGHVM: u32 = 0x00000001;
const SG_FVMLIB: u32 = 0x00000002;
const SG_NORELOC: u32 = 0x00000004;
const SG_PROTECTED_VERSION_1: u32 = 0x00000008;

// Define section flag masks
const SECTION_TYPE: u32 = 0x000000ff;
const SECTION_ATTRIBUTES: u32 = 0xffffff00;

// Define section types (use SECTION_TYPE mask)
const S_REGULAR: u32 = 0x00000000;
const S_ZEROFILL: u32 = 0x00000001;
const S_CSTRING_LITERALS: u32 = 0x00000002;
const S_4BYTE_LITERALS: u32 = 0x00000003;
const S_8BYTE_LITERALS: u32 = 0x00000004;
const S_LITERAL_POINTERS: u32 = 0x00000005;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x00000006;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x00000007;
const S_SYMBOL_STUBS: u32 = 0x00000008;
const S_MOD_INIT_FUNC_POINTERS: u32 = 0x00000009;
const S_MOD_TERM_FUNC_POINTERS: u32 = 0x0000000a;
const S_COALESCED: u32 = 0x0000000b;
const S_GB_ZEROFILL: u32 = 0x0000000c;
const S_INTERPOSING: u32 = 0x0000000d;
const S_16BYTE_LITERALS: u32 = 0x0000000e;
const S_DTRACE_DOF: u32 = 0x0000000f;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x00000010;
const S_THREAD_LOCAL_REGULAR: u32 = 0x00000011;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x00000012;
const S_THREAD_LOCAL_VARIABLES: u32 = 0x00000013;
const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x00000014;
const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x00000015;

// Define section attributes (use SECTION_ATTRIBUTES mask)
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x80000000; // Only pure instructions
const S_ATTR_NO_TOC: u32 = 0x40000000; // Contains coalesced symbols
const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x20000000; // Can strip static symbols
const S_ATTR_NO_DEAD_STRIP: u32 = 0x10000000; // No dead stripping
const S_ATTR_LIVE_SUPPORT: u32 = 0x08000000; // Live blocks support
const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x04000000; // Self modifying code
const S_ATTR_DEBUG: u32 = 0x02000000; // Debug section
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x00000400; // Some machine instructions
const S_ATTR_EXT_RELOC: u32 = 0x00000200; // Has external relocations
const S_ATTR_LOC_RELOC: u32 = 0x00000100; // Has local relocations

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
    let bytes = magic.to_ne_bytes();
    bytes[0] == 0xce || bytes[3] == 0xce
}

// If given file is BigEndian we want to swap bytes to LittleEndian
// If file is already in LittleEndian format return false
fn should_swap_bytes(magic: u32) -> bool {
    matches!(magic, MH_CIGAM | MH_CIGAM_64 | FAT_CIGAM | FAT_CIGAM_64)
}

// Change Mach-O RVA to offset
fn macho_rva_to_offset(address: u64, macho_proto: &Macho) -> Option<u64> {
    for segment in &macho_proto.segments {
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
fn macho_offset_to_rva(offset: u64, macho_proto: &Macho) -> Option<u64> {
    for segment in &macho_proto.segments {
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
    seg_count: &mut u64,
    macho_proto: &mut Macho,
) -> Result<(), String> {
    // Check if segment size is not less than SegmentCommand32 struct size
    if size < std::mem::size_of::<SegmentCommand32>() {
        return Err(
            "File section too small to contain segment section".to_string()
        );
    }

    // Parse segment command data
    let (remaining_data, mut sg) = parse_segment_command(command_data)
        .map_err(|e| format!("Parsing error: {:?}", e))?;
    if should_swap_bytes(
        macho_proto.magic.ok_or("Magic value not present in header")?,
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
            .map_err(|e| format!("Parsing error: {:?}", e))?;
        if should_swap_bytes(
            macho_proto.magic.ok_or("Magic value not present in header")?,
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
    macho_proto.segments.push(segment);
    *seg_count += 1;

    Ok(())
}

// Handle the LC_SEGMENT_64 command
fn handle_segment_command_64(
    command_data: &[u8],
    size: usize,
    seg_count: &mut u64,
    macho_proto: &mut Macho,
) -> Result<(), String> {
    // Check if segment size is not less than SegmentCommand64 struct size
    if size < std::mem::size_of::<SegmentCommand64>() {
        return Err(
            "File section too small to contain segment section".to_string()
        );
    }

    // Parse segment command data
    let (remaining_data, mut sg) = parse_segment_command_64(command_data)
        .map_err(|e| format!("Parsing error: {:?}", e))?;

    if should_swap_bytes(
        macho_proto.magic.ok_or("Magic value not present in header")?,
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
            .map_err(|e| format!("Parsing error: {:?}", e))?;
        if should_swap_bytes(
            macho_proto.magic.ok_or("Magic value not present in header")?,
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
    macho_proto.segments.push(segment);
    *seg_count += 1;

    Ok(())
}

// Handle UNIXTHREAD Command (older CPUs, replaced by LC_MAIN)
fn handle_unixthread(
    command_data: &[u8],
    size: usize,
    macho_proto: &mut Macho,
) -> Result<(), String> {
    if size < std::mem::size_of::<ThreadCommand>() {
        return Err(
            "File section too small to contain unixthread section".to_string()
        );
    }

    // Parse thread command
    let (remaining_data, thread_cmd) = parse_thread_command(command_data)
        .map_err(|e| format!("Parsing error: {:?}", e))?;

    // Check command size
    let command_size = std::cmp::min(size, thread_cmd.cmdsize as usize);
    if command_size < std::mem::size_of::<ThreadCommand>() {
        return Err("Invalid command size".to_string());
    }

    let thread_state_size =
        command_size - std::mem::size_of::<ThreadCommand>();
    let mut address: u64 = 0;
    let mut is64: bool = false;

    // Perform parsing according to cputype in header
    match macho_proto.cputype.ok_or("cputype value not present in header")? {
        CPU_TYPE_MC680X0 => {
            if thread_state_size >= std::mem::size_of::<M68KThreadState>() {
                let (_, state) = parse_m68k_thread_state(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.pc as u64;
            }
        }
        CPU_TYPE_MC88000 => {
            if thread_state_size >= std::mem::size_of::<M88KThreadState>() {
                let (_, state) = parse_m88k_thread_state(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.xip as u64;
            }
        }
        CPU_TYPE_SPARC => {
            if thread_state_size >= std::mem::size_of::<SPARCThreadState>() {
                let (_, state) = parse_sparc_thread_state(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.pc as u64;
            }
        }
        CPU_TYPE_POWERPC => {
            if thread_state_size >= std::mem::size_of::<PPCThreadState>() {
                let (_, state) = parse_ppc_thread_state(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.srr0 as u64;
            }
        }
        CPU_TYPE_X86 => {
            if thread_state_size >= std::mem::size_of::<X86ThreadState>() {
                let (_, state) = parse_x86_thread_state(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.eip as u64;
            }
        }
        CPU_TYPE_ARM => {
            if thread_state_size >= std::mem::size_of::<ARMThreadState>() {
                let (_, state) = parse_arm_thread_state(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.pc as u64;
            }
        }
        CPU_TYPE_X86_64 => {
            if thread_state_size >= std::mem::size_of::<X86ThreadState64>() {
                let (_, state) = parse_x86_thread_state64(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.rip;
                is64 = true;
            }
        }
        CPU_TYPE_ARM64 => {
            if thread_state_size >= std::mem::size_of::<ARMThreadState64>() {
                let (_, state) = parse_arm_thread_state64(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.pc;
                is64 = true;
            }
        }
        CPU_TYPE_POWERPC64 => {
            if thread_state_size >= std::mem::size_of::<PPCThreadState64>() {
                let (_, state) = parse_ppc_thread_state64(remaining_data)
                    .map_err(|e| format!("Parsing error: {:?}", e))?;
                address = state.srr0;
                is64 = true;
            }
        }
        _ => return Err("Unsupported CPU type".to_string()),
    }

    // Swap bytes if neccessary
    if should_swap_bytes(
        macho_proto.magic.ok_or("Magic value not present in header")?,
    ) {
        address = if is64 {
            address.swap_bytes()
        } else {
            (address as u32).swap_bytes() as u64
        };
    }

    // TODO: COMPILER FLAGS
    macho_proto.entry_point = macho_rva_to_offset(address, macho_proto);

    Ok(())
}

// Handle MAIN command
fn handle_main(
    command_data: &[u8],
    size: usize,
    macho_proto: &mut Macho,
) -> Result<(), String> {
    // Check size
    if size < std::mem::size_of::<EntryPointCommand>() {
        return Err(
            "File section too small to contain entrypoint section".to_string()
        );
    }

    // Parse main command
    let (_, mut entrypoint_cmd) = parse_entry_point_command(command_data)
        .map_err(|e| format!("Parsing error: {:?}", e))?;

    // Swap bytes if neccesarry
    if should_swap_bytes(
        macho_proto.magic.ok_or("Magic value not present in header")?,
    ) {
        swap_entry_point_command(&mut entrypoint_cmd);
    }

    // TODO: COMPILER FLAGS
    macho_proto.entry_point =
        macho_offset_to_rva(entrypoint_cmd.entryoff, macho_proto);

    macho_proto.set_stack_size(entrypoint_cmd.stacksize);

    Ok(())
}

// Handle Command Segment in Mach-O files according to Load Command value
fn handle_command(
    cmd: u32,
    cmdsize: usize,
    command_data: &[u8],
    seg_count: &mut u64,
    macho_proto: &mut Macho,
    process_segments: bool,
) {
    // Handly only segments, count segments
    if process_segments {
        match cmd {
            LC_SEGMENT => {
                if let Err(e) = handle_segment_command(
                    command_data,
                    cmdsize,
                    seg_count,
                    macho_proto,
                ) {
                    eprintln!("Error handling LC_SEGMENT: {}", e);
                }
            }
            LC_SEGMENT_64 => {
                if let Err(e) = handle_segment_command_64(
                    command_data,
                    cmdsize,
                    seg_count,
                    macho_proto,
                ) {
                    eprintln!("Error handling LC_SEGMENT_64: {}", e);
                }
            }
            _ => {}
        }
    // Handle rest of commands
    } else {
        match cmd {
            LC_UNIXTHREAD => {
                if let Err(e) =
                    handle_unixthread(command_data, cmdsize, macho_proto)
                {
                    eprintln!("Error handling LC_UNIXTHREAD: {}", e);
                }
            }
            LC_MAIN => {
                if let Err(e) = handle_main(command_data, cmdsize, macho_proto)
                {
                    eprintln!("Error handling LC_MAIN: {}", e);
                }
            }
            _ => {}
        }
    }
}

// Parse Mach-O commands
fn parse_macho_commands(
    data: &[u8],
    macho_proto: &mut Macho,
    process_segments: bool,
) -> Result<u64, String> {
    let header_size = if is_32_bit(
        macho_proto.magic.ok_or("Magic value not present in header")?,
    ) {
        std::mem::size_of::<MachOHeader32>()
    } else {
        std::mem::size_of::<MachOHeader64>()
    };

    let mut seg_count = 0;
    let mut command_offset = header_size;

    // Loop over Mach-O commands
    for _ in 0..macho_proto
        .ncmds
        .ok_or("Number of commands not present in header")?
    {
        // Check if remaining data is not less than size of LoadCommand
        if data.len() - command_offset < std::mem::size_of::<LoadCommand>() {
            break;
        }

        // Parse load commands from Mach-O file
        let command_data = &data[command_offset..];
        let (_, mut command) = parse_load_command(command_data)
            .map_err(|e| format!("Parsing error: {:?}", e))?;
        if should_swap_bytes(
            macho_proto.magic.ok_or("Magic value not present in header")?,
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

        handle_command(
            command.cmd,
            command.cmdsize as usize,
            command_data,
            &mut seg_count,
            macho_proto,
            process_segments,
        );

        // Continue to next command offset
        command_offset += command.cmdsize as usize;
    }

    Ok(seg_count)
}

// Parse basic Mach-O file
fn parse_macho_file(
    data: &[u8],
    macho_proto: &mut Macho,
) -> Result<(), String> {
    // File is too small to contain Mach-O header
    if data.len() < std::mem::size_of::<MachOHeader64>() {
        return Err("File is too small".to_string());
    }

    let (_, mut parsed_header) = parse_macho_header(data)
        .map_err(|e| format!("Parsing error: {:?}", e))?;
    // Byte conversion (swap) if necessary
    if should_swap_bytes(parsed_header.magic) {
        swap_mach_header(&mut parsed_header);
    }

    // Populate protobuf header section
    macho_proto.set_magic(parsed_header.magic);
    macho_proto.set_cputype(parsed_header.cputype);
    macho_proto.set_cpusubtype(parsed_header.cpusubtype);
    macho_proto.set_filetype(parsed_header.filetype);
    macho_proto.set_ncmds(parsed_header.ncmds);
    macho_proto.set_sizeofcmds(parsed_header.sizeofcmds);
    macho_proto.set_flags(parsed_header.flags);
    if !is_32_bit(parsed_header.magic) {
        macho_proto.set_reserved(parsed_header.reserved);
    }

    // Populate number of segments based on return type
    match parse_macho_commands(data, macho_proto, true) {
        Ok(result) => {
            macho_proto.set_number_of_segments(result);
        }
        Err(e) => return Err(e),
    }

    // Populate other fields
    parse_macho_commands(data, macho_proto, false)?;

    Ok(())
}

// Set all Mach-O definitions
fn set_definitions(macho_proto: &mut Macho) {
    // Set magic constants
    macho_proto.set_MH_MAGIC(MH_MAGIC);
    macho_proto.set_MH_CIGAM(MH_CIGAM);
    macho_proto.set_MH_MAGIC_64(MH_MAGIC_64);
    macho_proto.set_MH_CIGAM_64(MH_CIGAM_64);

    // Set FAT magic constants
    macho_proto.set_FAT_MAGIC(FAT_MAGIC);
    macho_proto.set_FAT_CIGAM(FAT_CIGAM);
    macho_proto.set_FAT_MAGIC_64(FAT_MAGIC_64);
    macho_proto.set_FAT_CIGAM_64(FAT_CIGAM_64);

    // Set 64bit masks
    macho_proto.set_CPU_ARCH_ABI64(CPU_ARCH_ABI64);
    macho_proto.set_CPU_SUBTYPE_LIB64(CPU_SUBTYPE_LIB64);

    // Set CPU types
    macho_proto.set_CPU_TYPE_MC680X0(CPU_TYPE_MC680X0);
    macho_proto.set_CPU_TYPE_X86(CPU_TYPE_X86);
    macho_proto.set_CPU_TYPE_I386(CPU_TYPE_X86);
    macho_proto.set_CPU_TYPE_X86_64(CPU_TYPE_X86_64);
    macho_proto.set_CPU_TYPE_MIPS(CPU_TYPE_MIPS);
    macho_proto.set_CPU_TYPE_MC98000(CPU_TYPE_MC98000);
    macho_proto.set_CPU_TYPE_ARM(CPU_TYPE_ARM);
    macho_proto.set_CPU_TYPE_ARM64(CPU_TYPE_ARM64);
    macho_proto.set_CPU_TYPE_MC88000(CPU_TYPE_MC88000);
    macho_proto.set_CPU_TYPE_SPARC(CPU_TYPE_SPARC);
    macho_proto.set_CPU_TYPE_POWERPC(CPU_TYPE_POWERPC);
    macho_proto.set_CPU_TYPE_POWERPC64(CPU_TYPE_POWERPC64);

    // Set CPU subtypes
    macho_proto.set_CPU_SUBTYPE_INTEL_MODEL_ALL(CPU_SUBTYPE_INTEL_MODEL_ALL);
    macho_proto.set_CPU_SUBTYPE_386(CPU_SUBTYPE_386);
    macho_proto.set_CPU_SUBTYPE_I386_ALL(CPU_SUBTYPE_386);
    macho_proto.set_CPU_SUBTYPE_X86_64_ALL(CPU_SUBTYPE_386);
    macho_proto.set_CPU_SUBTYPE_486(CPU_SUBTYPE_486);
    macho_proto.set_CPU_SUBTYPE_486SX(CPU_SUBTYPE_486SX);
    macho_proto.set_CPU_SUBTYPE_586(CPU_SUBTYPE_586);
    macho_proto.set_CPU_SUBTYPE_PENT(CPU_SUBTYPE_PENT);
    macho_proto.set_CPU_SUBTYPE_PENTPRO(CPU_SUBTYPE_PENTPRO);
    macho_proto.set_CPU_SUBTYPE_PENTII_M3(CPU_SUBTYPE_PENTII_M3);
    macho_proto.set_CPU_SUBTYPE_PENTII_M5(CPU_SUBTYPE_PENTII_M5);
    macho_proto.set_CPU_SUBTYPE_CELERON(CPU_SUBTYPE_CELERON);
    macho_proto.set_CPU_SUBTYPE_CELERON_MOBILE(CPU_SUBTYPE_CELERON_MOBILE);
    macho_proto.set_CPU_SUBTYPE_PENTIUM_3(CPU_SUBTYPE_PENTIUM_3);
    macho_proto.set_CPU_SUBTYPE_PENTIUM_3_M(CPU_SUBTYPE_PENTIUM_3_M);
    macho_proto.set_CPU_SUBTYPE_PENTIUM_3_XEON(CPU_SUBTYPE_PENTIUM_3_XEON);
    macho_proto.set_CPU_SUBTYPE_PENTIUM_M(CPU_SUBTYPE_PENTIUM_M);
    macho_proto.set_CPU_SUBTYPE_PENTIUM_4(CPU_SUBTYPE_PENTIUM_4);
    macho_proto.set_CPU_SUBTYPE_PENTIUM_4_M(CPU_SUBTYPE_PENTIUM_4_M);
    macho_proto.set_CPU_SUBTYPE_ITANIUM(CPU_SUBTYPE_ITANIUM);
    macho_proto.set_CPU_SUBTYPE_ITANIUM_2(CPU_SUBTYPE_ITANIUM_2);
    macho_proto.set_CPU_SUBTYPE_XEON(CPU_SUBTYPE_XEON);
    macho_proto.set_CPU_SUBTYPE_XEON_MP(CPU_SUBTYPE_XEON_MP);
    macho_proto.set_CPU_SUBTYPE_ARM_ALL(CPU_SUBTYPE_ARM_ALL);
    macho_proto.set_CPU_SUBTYPE_ARM_V4T(CPU_SUBTYPE_ARM_V4T);
    macho_proto.set_CPU_SUBTYPE_ARM_V6(CPU_SUBTYPE_ARM_V6);
    macho_proto.set_CPU_SUBTYPE_ARM_V5(CPU_SUBTYPE_ARM_V5);
    macho_proto.set_CPU_SUBTYPE_ARM_V5TEJ(CPU_SUBTYPE_ARM_V5TEJ);
    macho_proto.set_CPU_SUBTYPE_ARM_XSCALE(CPU_SUBTYPE_ARM_XSCALE);
    macho_proto.set_CPU_SUBTYPE_ARM_V7(CPU_SUBTYPE_ARM_V7);
    macho_proto.set_CPU_SUBTYPE_ARM_V7F(CPU_SUBTYPE_ARM_V7F);
    macho_proto.set_CPU_SUBTYPE_ARM_V7S(CPU_SUBTYPE_ARM_V7S);
    macho_proto.set_CPU_SUBTYPE_ARM_V7K(CPU_SUBTYPE_ARM_V7K);
    macho_proto.set_CPU_SUBTYPE_ARM_V6M(CPU_SUBTYPE_ARM_V6M);
    macho_proto.set_CPU_SUBTYPE_ARM_V7M(CPU_SUBTYPE_ARM_V7M);
    macho_proto.set_CPU_SUBTYPE_ARM_V7EM(CPU_SUBTYPE_ARM_V7EM);
    macho_proto.set_CPU_SUBTYPE_ARM64_ALL(CPU_SUBTYPE_ARM64_ALL);
    macho_proto.set_CPU_SUBTYPE_SPARC_ALL(CPU_SUBTYPE_SPARC_ALL);
    macho_proto.set_CPU_SUBTYPE_POWERPC_ALL(CPU_SUBTYPE_POWERPC_ALL);
    macho_proto.set_CPU_SUBTYPE_MC980000_ALL(CPU_SUBTYPE_MC980000_ALL);
    macho_proto.set_CPU_SUBTYPE_POWERPC_601(CPU_SUBTYPE_POWERPC_601);
    macho_proto.set_CPU_SUBTYPE_MC98601(CPU_SUBTYPE_MC98601);
    macho_proto.set_CPU_SUBTYPE_POWERPC_602(CPU_SUBTYPE_POWERPC_602);
    macho_proto.set_CPU_SUBTYPE_POWERPC_603(CPU_SUBTYPE_POWERPC_603);
    macho_proto.set_CPU_SUBTYPE_POWERPC_603E(CPU_SUBTYPE_POWERPC_603E);
    macho_proto.set_CPU_SUBTYPE_POWERPC_603EV(CPU_SUBTYPE_POWERPC_603EV);
    macho_proto.set_CPU_SUBTYPE_POWERPC_604(CPU_SUBTYPE_POWERPC_604);
    macho_proto.set_CPU_SUBTYPE_POWERPC_604E(CPU_SUBTYPE_POWERPC_604E);
    macho_proto.set_CPU_SUBTYPE_POWERPC_620(CPU_SUBTYPE_POWERPC_620);
    macho_proto.set_CPU_SUBTYPE_POWERPC_750(CPU_SUBTYPE_POWERPC_750);
    macho_proto.set_CPU_SUBTYPE_POWERPC_7400(CPU_SUBTYPE_POWERPC_7400);
    macho_proto.set_CPU_SUBTYPE_POWERPC_7450(CPU_SUBTYPE_POWERPC_7450);
    macho_proto.set_CPU_SUBTYPE_POWERPC_970(CPU_SUBTYPE_POWERPC_970);

    // Set file types
    macho_proto.set_MH_OBJECT(MH_OBJECT);
    macho_proto.set_MH_EXECUTE(MH_EXECUTE);
    macho_proto.set_MH_FVMLIB(MH_FVMLIB);
    macho_proto.set_MH_CORE(MH_CORE);
    macho_proto.set_MH_PRELOAD(MH_PRELOAD);
    macho_proto.set_MH_DYLIB(MH_DYLIB);
    macho_proto.set_MH_DYLINKER(MH_DYLINKER);
    macho_proto.set_MH_BUNDLE(MH_BUNDLE);
    macho_proto.set_MH_DYLIB_STUB(MH_DYLIB_STUB);
    macho_proto.set_MH_DSYM(MH_DSYM);
    macho_proto.set_MH_KEXT_BUNDLE(MH_KEXT_BUNDLE);

    // Set header flags
    macho_proto.set_MH_NOUNDEFS(MH_NOUNDEFS);
    macho_proto.set_MH_INCRLINK(MH_INCRLINK);
    macho_proto.set_MH_DYLDLINK(MH_DYLDLINK);
    macho_proto.set_MH_BINDATLOAD(MH_BINDATLOAD);
    macho_proto.set_MH_PREBOUND(MH_PREBOUND);
    macho_proto.set_MH_SPLIT_SEGS(MH_SPLIT_SEGS);
    macho_proto.set_MH_LAZY_INIT(MH_LAZY_INIT);
    macho_proto.set_MH_TWOLEVEL(MH_TWOLEVEL);
    macho_proto.set_MH_FORCE_FLAT(MH_FORCE_FLAT);
    macho_proto.set_MH_NOMULTIDEFS(MH_NOMULTIDEFS);
    macho_proto.set_MH_NOFIXPREBINDING(MH_NOFIXPREBINDING);
    macho_proto.set_MH_PREBINDABLE(MH_PREBINDABLE);
    macho_proto.set_MH_ALLMODSBOUND(MH_ALLMODSBOUND);
    macho_proto.set_MH_SUBSECTIONS_VIA_SYMBOLS(MH_SUBSECTIONS_VIA_SYMBOLS);
    macho_proto.set_MH_CANONICAL(MH_CANONICAL);
    macho_proto.set_MH_WEAK_DEFINES(MH_WEAK_DEFINES);
    macho_proto.set_MH_BINDS_TO_WEAK(MH_BINDS_TO_WEAK);
    macho_proto.set_MH_ALLOW_STACK_EXECUTION(MH_ALLOW_STACK_EXECUTION);
    macho_proto.set_MH_ROOT_SAFE(MH_ROOT_SAFE);
    macho_proto.set_MH_SETUID_SAFE(MH_SETUID_SAFE);
    macho_proto.set_MH_NO_REEXPORTED_DYLIBS(MH_NO_REEXPORTED_DYLIBS);
    macho_proto.set_MH_PIE(MH_PIE);
    macho_proto.set_MH_DEAD_STRIPPABLE_DYLIB(MH_DEAD_STRIPPABLE_DYLIB);
    macho_proto.set_MH_HAS_TLV_DESCRIPTORS(MH_HAS_TLV_DESCRIPTORS);
    macho_proto.set_MH_NO_HEAP_EXECUTION(MH_NO_HEAP_EXECUTION);
    macho_proto.set_MH_APP_EXTENSION_SAFE(MH_APP_EXTENSION_SAFE);

    // Set segment flags masks
    macho_proto.set_SG_HIGHVM(SG_HIGHVM);
    macho_proto.set_SG_FVMLIB(SG_FVMLIB);
    macho_proto.set_SG_NORELOC(SG_NORELOC);
    macho_proto.set_SG_PROTECTED_VERSION_1(SG_PROTECTED_VERSION_1);

    // Set section flags masks
    macho_proto.set_SECTION_TYPE(SECTION_TYPE);
    macho_proto.set_SECTION_ATTRIBUTES(SECTION_ATTRIBUTES);

    // Set section types
    macho_proto.set_S_REGULAR(S_REGULAR);
    macho_proto.set_S_ZEROFILL(S_ZEROFILL);
    macho_proto.set_S_CSTRING_LITERALS(S_CSTRING_LITERALS);
    macho_proto.set_S_4BYTE_LITERALS(S_4BYTE_LITERALS);
    macho_proto.set_S_8BYTE_LITERALS(S_8BYTE_LITERALS);
    macho_proto.set_S_NON_LAZY_SYMBOL_POINTERS(S_NON_LAZY_SYMBOL_POINTERS);
    macho_proto.set_S_LAZY_SYMBOL_POINTERS(S_LAZY_SYMBOL_POINTERS);
    macho_proto.set_S_LITERAL_POINTERS(S_LITERAL_POINTERS);
    macho_proto.set_S_SYMBOL_STUBS(S_SYMBOL_STUBS);
    macho_proto.set_S_MOD_INIT_FUNC_POINTERS(S_MOD_INIT_FUNC_POINTERS);
    macho_proto.set_S_MOD_TERM_FUNC_POINTERS(S_MOD_TERM_FUNC_POINTERS);
    macho_proto.set_S_COALESCED(S_COALESCED);
    macho_proto.set_S_GB_ZEROFILL(S_GB_ZEROFILL);
    macho_proto.set_S_INTERPOSING(S_INTERPOSING);
    macho_proto.set_S_16BYTE_LITERALS(S_16BYTE_LITERALS);
    macho_proto.set_S_DTRACE_DOF(S_DTRACE_DOF);
    macho_proto.set_S_LAZY_DYLIB_SYMBOL_POINTERS(S_LAZY_DYLIB_SYMBOL_POINTERS);
    macho_proto.set_S_THREAD_LOCAL_REGULAR(S_THREAD_LOCAL_REGULAR);
    macho_proto.set_S_THREAD_LOCAL_ZEROFILL(S_THREAD_LOCAL_ZEROFILL);
    macho_proto.set_S_THREAD_LOCAL_VARIABLES(S_THREAD_LOCAL_VARIABLES);
    macho_proto.set_S_THREAD_LOCAL_VARIABLE_POINTERS(
        S_THREAD_LOCAL_VARIABLE_POINTERS,
    );
    macho_proto.set_S_THREAD_LOCAL_INIT_FUNCTION_POINTERS(
        S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
    );

    // Set section attributes
    macho_proto.set_S_ATTR_PURE_INSTRUCTIONS(S_ATTR_PURE_INSTRUCTIONS);
    macho_proto.set_S_ATTR_NO_TOC(S_ATTR_NO_TOC);
    macho_proto.set_S_ATTR_STRIP_STATIC_SYMS(S_ATTR_STRIP_STATIC_SYMS);
    macho_proto.set_S_ATTR_NO_DEAD_STRIP(S_ATTR_NO_DEAD_STRIP);
    macho_proto.set_S_ATTR_LIVE_SUPPORT(S_ATTR_LIVE_SUPPORT);
    macho_proto.set_S_ATTR_SELF_MODIFYING_CODE(S_ATTR_SELF_MODIFYING_CODE);
    macho_proto.set_S_ATTR_DEBUG(S_ATTR_DEBUG);
    macho_proto.set_S_ATTR_SOME_INSTRUCTIONS(S_ATTR_SOME_INSTRUCTIONS);
    macho_proto.set_S_ATTR_EXT_RELOC(S_ATTR_EXT_RELOC);
    macho_proto.set_S_ATTR_LOC_RELOC(S_ATTR_LOC_RELOC);
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
}

#[module_main]
fn main(ctx: &ScanContext) -> Macho {
    // Create an empty instance of the Mach-O protobuf
    let mut macho_proto = Macho::new();

    // Get a &[u8] slice with the content of the file being scanned.
    let data = ctx.scanned_data();

    // If data is too short to be valid Mach-O file, return empty protobuf
    if data.len() < VALID_MACHO_LENGTH {
        eprintln!("Data is too short to be a valid Mach-O file.");
        return macho_proto;
    }

    // parse basic Mach-O file
    if is_macho_file_block(data) {
        if let Err(error) = parse_macho_file(data, &mut macho_proto) {
            eprintln!("Error while parsing Mach-O file: {}", error);
        }
    }

    if is_fat_macho_file_block(data) {
        //parse_fat_macho_file(data, &mut macho_proto);
    }

    set_definitions(&mut macho_proto);

    print_macho_info(&macho_proto);
    macho_proto
}
