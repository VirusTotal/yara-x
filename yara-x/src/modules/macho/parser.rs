use crate::modules::protos;
use bstr::{BStr, ByteSlice};
#[cfg(feature = "logging")]
use log::error;
use nom::bytes::complete::take;
use nom::combinator::{cond, map, verify};
use nom::multi::{count, length_count};
use nom::number::complete::{be_u32, le_u32, le_u64, u32, u64};
use nom::number::Endianness;
use nom::sequence::tuple;
use nom::{Err, IResult, Parser};
use protobuf::MessageField;

type Error<'a> = nom::error::Error<&'a [u8]>;

/// Mach-O magic constants
const MH_MAGIC: u32 = 0xfeedface;
const MH_CIGAM: u32 = 0xcefaedfe;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;

/// Mach-O FAT magic constants
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;
const FAT_MAGIC_64: u32 = 0xcafebabf;
const FAT_CIGAM_64: u32 = 0xbfbafeca;

/// Mach-O dynamic linker constant
const LC_REQ_DYLD: u32 = 0x80000000;

/// Mach-O load commands
const LC_SEGMENT: u32 = 0x00000001;
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
const LC_DYLD_ENVIRONMENT: u32 = 0x00000027;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
const LC_SOURCE_VERSION: u32 = 0x0000002a;

/// Mach-O CPU types
const CPU_TYPE_MC680X0: u32 = 0x00000006;
const CPU_TYPE_X86: u32 = 0x00000007;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM: u32 = 0x0000000c;
const CPU_TYPE_ARM64: u32 = 0x0100000c;
const CPU_TYPE_MC88000: u32 = 0x0000000d;
const CPU_TYPE_SPARC: u32 = 0x0000000e;
const CPU_TYPE_POWERPC: u32 = 0x00000012;
const CPU_TYPE_POWERPC64: u32 = 0x01000012;

/// Represents a Mach-O file. It can represent both a multi-architecture
/// binary (a.k.a. FAT binary) or a single-architecture binary.
pub struct MachO<'a> {
    /// When representing a FAT binary, this contains the file magic. It's
    /// `None` when the Mach-O file is a single-architecture binary.
    fat_magic: Option<u32>,
    /// When representing a FAT binary, this array contains one entry per
    /// architecture supported by the FAT binary. In such case the number of
    /// entries in this array should be equal to the number of entries in the
    /// `files` array. When representing a single-architecture Mach-O, this
    /// array is empty.
    archs: Vec<FatArch>,
    /// This array contains an entry per architecture included in the Mach-O
    /// file. For single-architecture binaries the array contains a single
    /// entry.
    files: Vec<MachOFile<'a>>,
}

impl<'a> MachO<'a> {
    /// Given the content of Macho-O file, parses it and returns a [`MachO`]
    /// object representing the file.
    pub fn parse(data: &'a [u8]) -> Result<Self, Err<Error<'a>>> {
        let (_, magic) = le_u32(data)?;

        if matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64)
        {
            Self::parse_fat_macho_file(data)
        } else {
            Ok(Self {
                fat_magic: None,
                archs: Vec::new(),
                files: vec![Self::parse_macho_file(data)?],
            })
        }
    }
}

impl<'a> MachO<'a> {
    /// Parses a FAT Mach-O file.
    fn parse_fat_macho_file(data: &'a [u8]) -> Result<Self, Err<Error<'a>>> {
        // Parse the magic number and make sure it's valid for a FAT
        // Mach-O file.
        let (remainder, magic) = verify(be_u32, |magic| {
            matches!(
                *magic,
                FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64
            )
        })
        .parse(data)?;

        // The magic number indicates the endianness.
        let endianness = match magic {
            FAT_MAGIC | FAT_MAGIC_64 => Endianness::Big,
            FAT_CIGAM | FAT_CIGAM_64 => Endianness::Little,
            _ => unreachable!(),
        };

        // The magic number also indicates whether this is a 32-bits or
        // 64-bits binary.
        let is_32_bits = match magic {
            FAT_MAGIC | FAT_CIGAM => true,
            FAT_MAGIC_64 | FAT_CIGAM_64 => false,
            _ => unreachable!(),
        };

        // After the magic comes an u32 with the number of `fat_arch`
        // structures that follow (`fat_arch64` for 64-bits binaries). Each
        // structure describes an individual Mach-O file included in the FAT
        // binary.
        let (_, archs) = length_count(
            // number of architectures.
            u32(endianness),
            // fat_arch/fat_arch64 structure.
            map(
                tuple((
                    u32(endianness),                    // cputype
                    u32(endianness),                    // cpusubtype
                    uint(endianness, is_32_bits),       // offset
                    uint(endianness, is_32_bits),       // size
                    u32(endianness),                    // align
                    cond(!is_32_bits, u32(endianness)), // reserved
                )),
                |(cputype, cpusubtype, offset, size, align, reserved)| {
                    FatArch {
                        cputype,
                        cpusubtype,
                        offset,
                        size,
                        align,
                        reserved: reserved.unwrap_or_default(),
                    }
                },
            ),
        )(remainder)?;

        let mut files = Vec::new();

        // Parse each of the individual Mach-O files contained in the FAT
        // binary. Errors that occur while parsing individual Mach-O files are
        // not propagated. If the FAT file is truncated for example, we may be
        // able to parse some of the Mach-O files while the rest can't be
        // parsed, but we still consider that case a success.
        for arch in &archs {
            let start = arch.offset as usize;
            let end = start.saturating_add(arch.size as usize);

            if let Some(macho) = data.get(start..end) {
                match Self::parse_macho_file(macho) {
                    Ok(macho) => files.push(macho),
                    Err(err) => {
                        #[cfg(feature = "logging")]
                        error!("Error parsing Mach-O file: {:?}", err);
                    }
                }
            };
        }

        Ok(MachO { fat_magic: Some(magic), archs, files })
    }

    /// Parses a single-architecture Mach-O file.
    fn parse_macho_file(data: &'a [u8]) -> Result<MachOFile, Err<Error<'a>>> {
        let (remainder, magic) = verify(be_u32, |magic| {
            matches!(*magic, MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64)
        })
        .parse(data)?;

        let endianness = match magic {
            MH_MAGIC | MH_MAGIC_64 => Endianness::Big,
            MH_CIGAM | MH_CIGAM_64 => Endianness::Little,
            _ => unreachable!(),
        };

        let is_32_bits = match magic {
            MH_MAGIC | MH_CIGAM => true,
            MH_MAGIC_64 | MH_CIGAM_64 => false,
            _ => unreachable!(),
        };

        let (mut commands, header) = map(
            tuple((
                u32(endianness),                    // cputype
                u32(endianness),                    // cpusubtype
                u32(endianness),                    // filetype
                u32(endianness),                    // ncmds
                u32(endianness),                    // sizeofcmds,
                u32(endianness),                    // flags,
                cond(!is_32_bits, u32(endianness)), // reserved, only in 64-bits
            )),
            |(
                cputype,
                cpusubtype,
                filetype,
                ncmds,
                sizeofcmds,
                flags,
                reserved,
            )| {
                MachOHeader {
                    magic,
                    cputype,
                    cpusubtype,
                    filetype,
                    ncmds,
                    sizeofcmds,
                    flags,
                    reserved,
                }
            },
        )(remainder)?;

        let ncmds = header.ncmds as usize;
        let mut macho = MachOFile {
            endianness,
            is_32_bits,
            header,
            segments: Vec::new(),
            dylibs: Vec::new(),
            rpaths: Vec::new(),
            dysymtab: None,
            dynamic_linker: None,
            source_version: None,
            entry_point_offset: None,
            entry_point_rva: None,
            stack_size: None,
        };

        for _ in 0..ncmds {
            match macho.command()(commands) {
                Ok((c, _)) => commands = c,
                Err(err) => {
                    #[cfg(feature = "logging")]
                    error!("Error parsing Mach-O file: {:?}", err);
                }
            }
        }

        if let Some(entry_point_rva) = macho.entry_point_rva {
            macho.entry_point_offset = macho.rva_to_offset(entry_point_rva);
        }

        Ok(macho)
    }
}

pub struct MachOFile<'a> {
    endianness: Endianness,
    is_32_bits: bool,
    entry_point_offset: Option<u64>,
    entry_point_rva: Option<u64>,
    stack_size: Option<u64>,
    header: MachOHeader,
    segments: Vec<Segment<'a>>,
    dylibs: Vec<Dylib<'a>>,
    dysymtab: Option<Dysymtab>,
    dynamic_linker: Option<&'a [u8]>,
    source_version: Option<String>,
    rpaths: Vec<&'a [u8]>,
}

impl<'a> MachOFile<'a> {
    /// Converts a relative virtual address (RVA) to file object.
    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        for segment in &self.segments {
            let start = segment.vmaddr;
            let end = segment.vmaddr.checked_add(segment.vmsize)?;
            if rva >= start && rva < end {
                return segment.fileoff.checked_add(rva.checked_sub(start)?);
            }
        }
        None
    }
}

impl<'a> MachOFile<'a> {
    /// Parser that parses a Mach-O section.
    fn section(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Section> + '_ {
        map(
            tuple((
                // sectname
                map(take(16_usize), |name| {
                    BStr::new(name).trim_end_with(|c| c == '\0')
                }),
                // segname
                map(take(16_usize), |name| {
                    BStr::new(name).trim_end_with(|c| c == '\0')
                }),
                uint(self.endianness, self.is_32_bits), // addr
                uint(self.endianness, self.is_32_bits), // size
                u32(self.endianness),                   // offset
                u32(self.endianness),                   // align
                u32(self.endianness),                   // reloff
                u32(self.endianness),                   // nreloc
                u32(self.endianness),                   // flags
                u32(self.endianness),                   // reserved1
                u32(self.endianness),                   // reserved2
                cond(!self.is_32_bits, u32(self.endianness)), // reserved3
            )),
            |(
                sectname,
                segname,
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
            )| {
                Section {
                    sectname,
                    segname,
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
                }
            },
        )
    }

    /// Parser that parses a Mach-O command.
    fn command(
        &mut self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        move |input: &'a [u8]| {
            // The first two u32 in the command are the value that indicates
            // the command type, and the size of the command's data.
            let (remainder, (command, command_size)) = tuple((
                u32(self.endianness), // command
                u32(self.endianness), // command_size
            ))(input)?;

            // Take the command's data.
            let (remainder, command_data) = take(
                // `command_size` includes the sizes of `command` and
                // `command_size` itself, which is 8 bytes in total. So,
                // the size of the command's data is actually `command_size`
                // minus 8.
                command_size.saturating_sub(8),
            )(remainder)?;

            // Parse the command's data. Parsers for individual commands must
            // consume all `command_data`.
            match command {
                LC_MAIN => {
                    let (_, (entry_point_offset, stack_size)) =
                        self.main_command()(command_data)?;
                    self.entry_point_offset = Some(entry_point_offset);
                    self.stack_size = Some(stack_size);
                }
                LC_UNIXTHREAD => {
                    let (_, eip) = self.thread_command()(command_data)?;
                    self.entry_point_rva = Some(eip);
                }
                LC_SEGMENT | LC_SEGMENT_64 => {
                    let (_, segment) = self.segment_command()(command_data)?;
                    self.segments.push(segment);
                }
                LC_RPATH => {
                    let (_, rpath) = self.rpath_command()(command_data)?;
                    self.rpaths.push(rpath);
                }
                LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB
                | LC_REEXPORT_DYLIB => {
                    let (_, dylib) = self.dylib_command()(command_data)?;
                    self.dylibs.push(dylib);
                }
                LC_SOURCE_VERSION => {
                    let (_, ver) =
                        self.source_version_command()(command_data)?;
                    self.source_version =
                        Some(convert_to_source_version_string(ver));
                }
                LC_ID_DYLINKER | LC_LOAD_DYLINKER | LC_DYLD_ENVIRONMENT => {
                    let (_, dylinker) = self.dylinker_command()(command_data)?;
                    self.dynamic_linker = Some(dylinker.name);
                }
                LC_DYSYMTAB => {
                    let (_, dysymtab) = self.dysymtab_command()(command_data)?;
                    self.dysymtab = Some(dysymtab);
                }
                _ => {}
            }

            Ok((remainder, ()))
        }
    }

    /// Parser that parses a LC_MAIN command.
    fn main_command(
        &mut self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], (u64, u64)> + '_ {
        tuple((
            u64(self.endianness), // entryoff,
            u64(self.endianness), // stacksize,
        ))
    }

    /// Parser that parses a LC_UNIXTHREAD command.
    fn thread_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        move |input: &'a [u8]| {
            let (remainder, (_flavor, _count)) = tuple((
                u32(self.endianness), // flavor
                u32(self.endianness), // count
            ))(input)?;

            match self.header.cputype {
                CPU_TYPE_X86 => self.x86_thread_state()(remainder),
                CPU_TYPE_X86_64 => self.x86_64_thread_state()(remainder),
                CPU_TYPE_ARM => self.arm_thread_state()(remainder),
                CPU_TYPE_ARM64 => self.arm64_thread_state()(remainder),
                CPU_TYPE_POWERPC => self.ppc_thread_state()(remainder),
                CPU_TYPE_POWERPC64 => self.ppc64_thread_state()(remainder),
                CPU_TYPE_MC680X0 => self.m68k_thread_state()(remainder),
                CPU_TYPE_MC88000 => self.m88k_thread_state()(remainder),
                CPU_TYPE_SPARC => self.sparc_thread_state()(remainder),
                _ => Ok((remainder, 0)),
            }
        }
    }

    /// Parser that parses a LC_SEGMENT or LC_SEGMENT_64 command.
    fn segment_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Segment> + '_ {
        move |input: &'a [u8]| {
            let (
                remainder,
                (
                    segname,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    nsects,
                    flags,
                ),
            ) = tuple((
                // name
                map(take(16_usize), |name| {
                    BStr::new(name).trim_end_with(|c| c == '\0')
                }),
                uint(self.endianness, self.is_32_bits), // vmaddr
                uint(self.endianness, self.is_32_bits), // vmsize
                uint(self.endianness, self.is_32_bits), // fileoff
                uint(self.endianness, self.is_32_bits), // filesize,
                u32(self.endianness),                   // maxprot,
                u32(self.endianness),                   // initprot,
                u32(self.endianness),                   // nsects,
                u32(self.endianness),                   // flags,
            ))(input)?;

            let (remainder, sections) =
                count(self.section(), nsects as usize)(remainder)?;

            Ok((
                remainder,
                Segment {
                    segname,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    nsects,
                    flags,
                    sections,
                },
            ))
        }
    }

    /// Parser that parses a LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB
    /// or LC_REEXPORT_DYLIB command.
    fn dylib_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Dylib> + '_ {
        move |input: &'a [u8]| {
            let (
                remainder,
                (_offset, timestamp, current_version, compatibility_version),
            ) = tuple((
                u32(self.endianness), // offset,
                u32(self.endianness), // timestamp,
                u32(self.endianness), // current_version,
                u32(self.endianness), // compatibility_version,
            ))(input)?;

            Ok((
                &[],
                Dylib {
                    name: BStr::new(remainder).trim_end_with(|c| c == '\0'),
                    timestamp,
                    current_version,
                    compatibility_version,
                },
            ))
        }
    }

    /// Parser that parses a LC_DYSYMTAB command.
    fn dysymtab_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Dysymtab> + '_ {
        map(
            tuple((
                u32(self.endianness), //  ilocalsym
                u32(self.endianness), //  nlocalsym
                u32(self.endianness), //  iextdefsym
                u32(self.endianness), //  nextdefsym
                u32(self.endianness), //  tocoff
                u32(self.endianness), //  ntoc
                u32(self.endianness), //  modtaboff
                u32(self.endianness), //  nmodtab
                u32(self.endianness), //  extrefsymoff
                u32(self.endianness), //  nextrefsyms
                u32(self.endianness), //  indirectsymoff
                u32(self.endianness), //  nindirectsyms =
                u32(self.endianness), //  extreloff
                u32(self.endianness), //  nextrel
                u32(self.endianness), //  locreloff
                u32(self.endianness), //  nlocrel
            )),
            |(
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
            )| {
                Dysymtab {
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
                }
            },
        )
    }

    /// Parser that parses a LC_ID_DYLINKER, LC_LOAD_DYLINKER or
    /// LC_DYLD_ENVIRONMENT  command.
    fn dylinker_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Dylinker> + '_ {
        move |input: &'a [u8]| {
            let (remainder, _offset) = u32(self.endianness)(input)?;

            Ok((
                &[],
                Dylinker {
                    name: BStr::new(remainder).trim_end_with(|c| c == '\0'),
                },
            ))
        }
    }

    /// Parser that parses a LC_SOURCE_VERSION command.
    fn source_version_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        u64(self.endianness)
    }

    /// Parser that parses a LC_RPATH command.
    fn rpath_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], &'a [u8]> + '_ {
        move |input: &'a [u8]| {
            let (remainder, _) = u32(self.endianness)(input)?;

            Ok((&[], BStr::new(remainder).trim_end_with(|c| c == '\0')))
        }
    }

    fn x86_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                le_u32, // eax
                le_u32, // ebx
                le_u32, // ecx
                le_u32, // edx
                le_u32, // edi
                le_u32, // esi
                le_u32, // ebp
                le_u32, // esp
                le_u32, // ss
                le_u32, // eflags
                le_u32, // eip
                le_u32, // cs
                le_u32, // ds
                le_u32, // es
                le_u32, // fs
                le_u32, // gs
            )),
            |reg| reg.10 as u64, // eip,
        )
    }

    fn x86_64_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                le_u64, // rax
                le_u64, // rbx
                le_u64, // rcx
                le_u64, // rdx
                le_u64, // rdi
                le_u64, // rsi
                le_u64, // rbp
                le_u64, // rsp
                le_u64, // r8
                le_u64, // r9
                le_u64, // r10
                le_u64, // r11
                le_u64, // r12
                le_u64, // r13
                le_u64, // r14
                le_u64, // r15
                le_u64, // rip
                le_u64, // rflags
                le_u64, // cs
                le_u64, // fs
                le_u64, // gs
            )),
            |reg| reg.16, // eip,
        )
    }

    fn arm_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                count(le_u32, 13), // r
                le_u32,            // sp
                le_u32,            // lr
                le_u32,            // pc
                le_u32,            // cpsr
            )),
            |(_, _, _, pc, _)| pc as u64,
        )
    }

    fn arm64_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                count(le_u64, 29), // r
                le_u64,            // fp
                le_u64,            // lr
                le_u64,            // sp
                le_u64,            // pc
                le_u32,            // cpsr
            )),
            |(_, _, _, _, pc, _)| pc,
        )
    }

    fn ppc_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                uint(self.endianness, true),            // srr0
                uint(self.endianness, true),            // srr1
                count(uint(self.endianness, true), 32), // r
                uint(self.endianness, true),            // cr
                uint(self.endianness, true),            // xer
                uint(self.endianness, true),            // lr
                uint(self.endianness, true),            // ctr
                uint(self.endianness, true),            // mq
                uint(self.endianness, true),            // vrsavead
            )),
            |(srr0, _, _, _, _, _, _, _, _)| srr0,
        )
    }

    fn ppc64_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                uint(self.endianness, false),            // srr0
                uint(self.endianness, false),            // srr1
                count(uint(self.endianness, false), 32), // r
                uint(self.endianness, true),             // cr
                uint(self.endianness, false),            // xer
                uint(self.endianness, false),            // lr
                uint(self.endianness, false),            // ctr
                uint(self.endianness, false),            // vrsave
            )),
            |(srr0, _, _, _, _, _, _, _)| srr0,
        )
    }

    fn sparc_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                le_u32,           // psr
                le_u32,           // pc
                le_u32,           // npc
                le_u32,           // y
                count(le_u32, 7), // g
                count(le_u32, 7), // o
            )),
            |(_, pc, _, _, _, _)| pc as u64,
        )
    }

    fn m68k_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                count(le_u32, 8), // dreg
                count(le_u32, 8), // areg
                le_u32,           // pad
                le_u32,           // sr
                le_u32,           // pc
            )),
            |(_, _, _, _, pc)| pc as u64,
        )
    }

    fn m88k_thread_state(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u64> + '_ {
        map(
            tuple((
                count(le_u32, 31), // r
                le_u32,            // xip
                le_u32,            // xip_in_bd
                le_u32,            // nip
            )),
            |(_, xip, _, _)| xip as u64,
        )
    }
}

struct FatArch {
    cputype: u32,
    cpusubtype: u32,
    offset: u64,
    size: u64,
    align: u32,
    reserved: u32,
}

struct MachOHeader {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: Option<u32>, // Only set in 64-bits binary.
}

struct Segment<'a> {
    segname: &'a [u8],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,
    sections: Vec<Section<'a>>,
}

struct Section<'a> {
    sectname: &'a [u8],
    segname: &'a [u8],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: Option<u32>, // Only set in 64-bits binaries
}

struct Dylib<'a> {
    name: &'a [u8],
    timestamp: u32,
    current_version: u32,
    compatibility_version: u32,
}

struct Dylinker<'a> {
    name: &'a [u8],
}

struct Dysymtab {
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

/// Parser that reads a 32-bits or 64-bits
fn uint(
    endianness: Endianness,
    _32bits: bool,
) -> impl FnMut(&[u8]) -> IResult<&[u8], u64> {
    move |input: &[u8]| {
        if _32bits {
            let (remainder, i) = u32(endianness)(input)?;
            Ok((remainder, i as u64))
        } else {
            u64(endianness)(input)
        }
    }
}

/// Convert a decimal number representation to a version string representation.
fn convert_to_version_string(decimal_number: u32) -> String {
    let major = decimal_number >> 16;
    let minor = (decimal_number >> 8) & 0xFF;
    let patch = decimal_number & 0xFF;
    format!("{}.{}.{}", major, minor, patch)
}

/// Convert a decimal number representation to a source version string
/// representation.
fn convert_to_source_version_string(decimal_number: u64) -> String {
    let mask = 0x3f;
    let a = decimal_number >> 40;
    let b = (decimal_number >> 30) & mask;
    let c = (decimal_number >> 20) & mask;
    let d = (decimal_number >> 10) & mask;
    let e = decimal_number & mask;
    format!("{}.{}.{}.{}.{}", a, b, c, d, e)
}

impl From<MachO<'_>> for protos::macho::Macho {
    fn from(macho: MachO<'_>) -> Self {
        let mut result = protos::macho::Macho::new();
        // If the Mach-O file is a single-architecture binary, fill the fields
        // at the top level of `protos::macho::Macho` structure. If it is a
        // multi-architecture binary (FAT binary) then fill the `fat_arch`
        // and `file` arrays.
        if macho.files.len() == 1 {
            let m = macho.files.first().unwrap();
            result.set_magic(m.header.magic);
            result.set_ncmds(m.header.ncmds);
            result.set_cputype(m.header.cputype);
            result.set_cpusubtype(m.header.cpusubtype);
            result.set_filetype(m.header.filetype);
            result.set_flags(m.header.flags);
            result.set_sizeofcmds(m.header.sizeofcmds);
            result.reserved = m.header.reserved;
            result.entry_point = m.entry_point_offset;
            result.stack_size = m.stack_size;
            result.source_version = m.source_version.to_owned();
            result.dynamic_linker = m.dynamic_linker.map(|dl| dl.into());

            if let Some(dysymtab) = &m.dysymtab {
                result.dysymtab = MessageField::some(dysymtab.into());
            }

            result.segments.extend(m.segments.iter().map(|seg| seg.into()));
            result.dylibs.extend(m.dylibs.iter().map(|dylib| dylib.into()));
            result.rpaths.extend(m.rpaths.iter().map(|rpath| rpath.to_vec()));

            result
                .set_number_of_segments(m.segments.len().try_into().unwrap());
        } else {
            result.fat_magic = macho.fat_magic;
            result.set_nfat_arch(macho.archs.len().try_into().unwrap());
            result.fat_arch.extend(macho.archs.iter().map(|arch| arch.into()));
            result.file.extend(macho.files.iter().map(|file| file.into()));
        }
        result
    }
}

impl From<&MachOFile<'_>> for protos::macho::File {
    fn from(macho: &MachOFile<'_>) -> Self {
        let mut result = protos::macho::File::new();
        result.set_magic(macho.header.magic);
        result.set_ncmds(macho.header.ncmds);
        result.set_cputype(macho.header.cputype);
        result.set_cpusubtype(macho.header.cpusubtype);
        result.set_filetype(macho.header.filetype);
        result.set_flags(macho.header.flags);
        result.set_sizeofcmds(macho.header.sizeofcmds);
        result.reserved = macho.header.reserved;
        result.entry_point = macho.entry_point_offset;
        result.stack_size = macho.stack_size;
        result.source_version = macho.source_version.to_owned();
        result.dynamic_linker = macho.dynamic_linker.map(|dl| dl.into());

        if let Some(dysymtab) = &macho.dysymtab {
            result.dysymtab = MessageField::some(dysymtab.into());
        }

        result.segments.extend(macho.segments.iter().map(|seg| seg.into()));
        result.dylibs.extend(macho.dylibs.iter().map(|dylib| dylib.into()));
        result.rpaths.extend(macho.rpaths.iter().map(|rpath| rpath.to_vec()));

        result
            .set_number_of_segments(result.segments.len().try_into().unwrap());

        result
    }
}

impl From<&FatArch> for protos::macho::FatArch {
    fn from(arch: &FatArch) -> Self {
        let mut result = protos::macho::FatArch::new();
        result.set_cputype(arch.cputype);
        result.set_cpusubtype(arch.cpusubtype);
        result.set_offset(arch.offset);
        result.set_size(arch.size);
        result.set_align(arch.align);
        result.set_reserved(arch.reserved);
        result
    }
}

impl From<&Segment<'_>> for protos::macho::Segment {
    fn from(seg: &Segment<'_>) -> Self {
        let mut result = protos::macho::Segment::new();
        result.set_segname(seg.segname.into());
        result.set_vmaddr(seg.vmaddr);
        result.set_vmsize(seg.vmsize);
        result.set_fileoff(seg.fileoff);
        result.set_filesize(seg.filesize);
        result.set_maxprot(seg.maxprot);
        result.set_initprot(seg.initprot);
        result.set_nsects(seg.nsects);
        result.set_flags(seg.flags);
        result.sections.extend(seg.sections.iter().map(|sec| sec.into()));
        result
    }
}

impl From<&Section<'_>> for protos::macho::Section {
    fn from(sec: &Section<'_>) -> Self {
        let mut result = protos::macho::Section::new();
        result.set_segname(sec.segname.into());
        result.set_sectname(sec.sectname.into());
        result.set_addr(sec.addr);
        result.set_size(sec.size);
        result.set_offset(sec.offset);
        result.set_align(sec.align);
        result.set_reloff(sec.reloff);
        result.set_nreloc(sec.nreloc);
        result.set_flags(sec.flags);
        result.set_reserved1(sec.reserved1);
        result.set_reserved2(sec.reserved2);
        result.reserved3 = sec.reserved3;
        result
    }
}

impl From<&Dylib<'_>> for protos::macho::Dylib {
    fn from(dylib: &Dylib<'_>) -> Self {
        let mut result = protos::macho::Dylib::new();
        result.set_name(dylib.name.into());
        result.set_timestamp(dylib.timestamp);
        result.set_compatibility_version(convert_to_version_string(
            dylib.compatibility_version,
        ));
        result.set_current_version(convert_to_version_string(
            dylib.current_version,
        ));
        result
    }
}

impl From<&Dysymtab> for protos::macho::Dysymtab {
    fn from(dysymtab: &Dysymtab) -> Self {
        let mut result = protos::macho::Dysymtab::new();
        result.set_ilocalsym(dysymtab.ilocalsym);
        result.set_nlocalsym(dysymtab.nlocalsym);
        result.set_iextdefsym(dysymtab.iextdefsym);
        result.set_nextdefsym(dysymtab.nextdefsym);
        result.set_tocoff(dysymtab.tocoff);
        result.set_ntoc(dysymtab.ntoc);
        result.set_modtaboff(dysymtab.modtaboff);
        result.set_nmodtab(dysymtab.nmodtab);
        result.set_extrefsymoff(dysymtab.extrefsymoff);
        result.set_nextrefsyms(dysymtab.nextrefsyms);
        result.set_indirectsymoff(dysymtab.indirectsymoff);
        result.set_nindirectsyms(dysymtab.nindirectsyms);
        result.set_extreloff(dysymtab.extreloff);
        result.set_nextrel(dysymtab.nextrel);
        result.set_locreloff(dysymtab.locreloff);
        result.set_nlocrel(dysymtab.nlocrel);
        result
    }
}
