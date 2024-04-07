use std::mem;
use std::ops::Range;

use nom::bytes::complete::{take, take_till};
use nom::combinator::{map, map_res, verify};
use nom::multi::{count, many0};
use nom::number::complete::{le_u32, u16, u32, u64, u8};
use nom::number::Endianness;
use nom::sequence::tuple;
use nom::{Err, IResult, Parser};
use protobuf::EnumOrUnknown;

use crate::modules::protos::elf;

#[repr(u8)]
enum Class {
    Elf32 = 0x01,
    Elf64 = 0x02,
}

/// An ELF file parser.
pub struct ElfParser {
    result: elf::ELF,
    endianness: Endianness,
    class: Class,
}

impl ElfParser {
    /// Creates a new parser for ELF files.
    pub fn new() -> Self {
        Self {
            result: elf::ELF::default(),
            endianness: Endianness::Native,
            class: Class::Elf32,
        }
    }

    /// Parses an ELF file and produces a [`elf::ELF`] protobuf containing
    /// metadata extracted from the file.
    pub fn parse<'a>(
        &mut self,
        elf: &'a [u8],
    ) -> Result<elf::ELF, Err<nom::error::Error<&'a [u8]>>> {
        // Parse the ELF identifier.
        let (remainder, (_, class, data_encoding, _, _, _)) = tuple((
            // Magic must be 0x7f 0x45 (E) 0x4c (L) 0x46 (F).
            verify(le_u32, |magic| *magic == 0x464C457F),
            // Class must be either ELF_CLASS_32 or ELF_CLASS_64.
            verify(u8, |c| {
                *c == Self::ELF_CLASS_32 || *c == Self::ELF_CLASS_64
            }),
            // Data encoding must be either ELF_DATA_2LSB or ELF_DATA_2MSB
            verify(u8, |d| {
                *d == Self::ELF_DATA_2LSB || *d == Self::ELF_DATA_2MSB
            }),
            u8,            // version
            take(8_usize), // padding
            u8,            // nident
        ))(elf)?;

        match class {
            Self::ELF_CLASS_32 => self.class = Class::Elf32,
            Self::ELF_CLASS_64 => self.class = Class::Elf64,
            // `class` has been verified to be valid.
            _ => unreachable!(),
        }

        match data_encoding {
            Self::ELF_DATA_2LSB => {
                self.endianness = Endianness::Little;
            }
            Self::ELF_DATA_2MSB => {
                self.endianness = Endianness::Big;
            }
            // `data_encoding` has been verified to be valid.
            _ => unreachable!(),
        }

        // Parse the executable header.
        let (_remainder, ehdr) = self.parse_ehdr()(remainder)?;

        self.result.type_ =
            Some(EnumOrUnknown::<elf::Type>::from_i32(ehdr.type_.into()));

        self.result.machine =
            Some(EnumOrUnknown::<elf::Machine>::from_i32(ehdr.machine.into()));

        self.result.sh_offset = Some(ehdr.sh_offset);
        self.result.sh_entry_size = Some(ehdr.sh_entry_size.into());
        self.result.ph_offset = Some(ehdr.ph_offset);
        self.result.ph_entry_size = Some(ehdr.ph_entry_size.into());
        self.result.number_of_sections = Some(ehdr.sh_entry_count.into());
        self.result.number_of_segments = Some(ehdr.ph_entry_count.into());

        let segments = self.parse_segments(&ehdr, elf);
        let sections = self.parse_sections(&ehdr, elf);

        for s in segments.iter().flatten() {
            let mut segment = elf::Segment::new();
            segment.flags = Some(s.flags);
            segment.offset = Some(s.offset);
            segment.virtual_address = Some(s.virt_addr);
            segment.physical_address = Some(s.phys_addr);
            segment.file_size = Some(s.file_size);
            segment.memory_size = Some(s.mem_size);
            segment.alignment = Some(s.alignment);
            segment.type_ = s
                .type_
                .try_into()
                .ok()
                .map(EnumOrUnknown::<elf::SegmentType>::from_i32);

            self.result.segments.push(segment);

            if s.type_ == Self::ELF_PT_DYNAMIC {
                self.result.dynamic.extend(self.parse_dyn_entries(elf, s));
            }
        }

        self.result.dynamic_section_entries =
            Some(self.result.dynamic.len().try_into().unwrap());

        // If the number of sections is greater than ELF_SHN_LORESERVE the
        // header is probably corrupt, exit early.
        if ehdr.sh_entry_count >= Self::ELF_SHN_LORESERVE {
            return Ok(mem::take(&mut self.result));
        }

        if let Some(elf_type) = self.result.type_ {
            if ehdr.entry_point != 0 {
                self.result.entry_point = Self::rva_to_offset(
                    elf_type,
                    segments.as_deref().unwrap_or(&[]),
                    sections.as_deref().unwrap_or(&[]),
                    ehdr.entry_point,
                )
            }
        }

        let sections = match sections {
            Some(sections) => sections,
            None => return Ok(mem::take(&mut self.result)),
        };

        // Find the `.shstrtab` section, which is the section that contains
        // the section names. The `ehdr.sh_str_table_index` field contains the
        // index for that section in the section table.
        let shstrtab = sections.get(ehdr.sh_str_tab_index as usize);

        for s in sections.iter() {
            let mut section = elf::Section::new();

            section.flags = Some(s.flags);
            section.address = Some(s.addr);
            section.size = Some(s.size);
            section.offset = Some(s.offset);
            section.name = Self::parse_name(elf, shstrtab, s.name);
            section.type_ = s
                .type_
                .try_into()
                .ok()
                .map(EnumOrUnknown::<elf::SectionType>::from_i32);

            self.result.sections.push(section);
        }

        // Find the `.symtab` section and parse the symbol table.
        self.result.symtab.extend(self.parse_sym_table(
            elf,
            sections.as_slice(),
            |section| section.type_ == Self::ELF_SHT_SYMTAB,
        ));

        self.result.symtab_entries =
            Some(self.result.symtab.len().try_into().unwrap());

        // Find the `.dynsym` section and parse the dynamic linking symbols.
        self.result.dynsym.extend(self.parse_sym_table(
            elf,
            sections.as_slice(),
            |section| section.type_ == Self::ELF_SHT_DYNSYM,
        ));

        self.result.dynsym_entries =
            Some(self.result.dynsym.len().try_into().unwrap());

        Ok(mem::take(&mut self.result))
    }
}

impl ElfParser {
    const ELF_CLASS_32: u8 = 0x01;
    // 32-bit ELF file
    const ELF_CLASS_64: u8 = 0x02;
    // 64-bit ELF file
    const ELF_DATA_2LSB: u8 = 0x01;
    const ELF_DATA_2MSB: u8 = 0x02;
    const ELF_PT_DYNAMIC: u32 = 0x02;
    const ELF_SHN_LORESERVE: u16 = 0xFF00;
    const ELF_DT_NULL: u64 = 0;
    const ELF_SHT_NULL: u32 = 0;
    const ELF_SHT_SYMTAB: u32 = 2;
    const ELF_SHT_NOBITS: u32 = 8;
    const ELF_SHT_DYNSYM: u32 = 11;

    /// Parses an offset or address.
    ///
    /// The size of an offset or address in an ELF file depends on the class
    /// of file. It is an `u32` in 32-bits ELF files, and `u64` in 64-bits
    /// files. This parser consumes an `u32` while parsing 32-bits files, but
    /// always returns the value as an `u64`.
    fn off_or_addr(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], u64> + '_ {
        move |input: &[u8]| {
            let (remainder, value) = match self.class {
                Class::Elf32 => map_res(u32(self.endianness), |value| {
                    Ok::<u64, nom::error::Error<&[u8]>>(value as u64)
                })
                .parse(input)?,
                Class::Elf64 => u64(self.endianness).parse(input)?,
            };
            Ok((remainder, value))
        }
    }

    fn rva_to_offset(
        elf_type: EnumOrUnknown<elf::Type>,
        segments: &[Phdr],
        sections: &[Shdr],
        rva: u64,
    ) -> Option<u64> {
        match elf_type.enum_value() {
            Ok(elf::Type::ET_EXEC) => {
                for segment in segments.iter() {
                    if segment.virt_addr_range()?.contains(&rva) {
                        return segment
                            .offset
                            .checked_add(rva - segment.virt_addr);
                    }
                }
            }
            _ => {
                for section in sections.iter() {
                    if section.type_ != Self::ELF_SHT_NOBITS
                        && section.type_ != Self::ELF_SHT_NULL
                        && section.addr_range()?.contains(&rva)
                    {
                        return section.offset.checked_add(rva - section.addr);
                    }
                }
            }
        }
        None
    }

    fn parse_segments(&self, ehdr: &Ehdr, input: &[u8]) -> Option<Vec<Phdr>> {
        input.get(ehdr.ph_offset as usize..).and_then(|segments| {
            count(self.parse_phdr(), ehdr.ph_entry_count as usize)
                .parse(segments)
                .map(|(_, segments)| segments)
                .ok()
        })
    }

    fn parse_sections(&self, ehdr: &Ehdr, input: &[u8]) -> Option<Vec<Shdr>> {
        input.get(ehdr.sh_offset as usize..).and_then(|sections| {
            count(self.parse_shdr(), ehdr.sh_entry_count as usize)
                .parse(sections)
                .map(|(_, sections)| sections)
                .ok()
        })
    }

    fn parse_ehdr(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Ehdr> + '_ {
        move |input: &[u8]| {
            let remainder: &[u8];
            let mut ehdr = Ehdr::default();
            (
                remainder,
                (
                    ehdr.type_,
                    ehdr.machine,
                    ehdr.version,
                    ehdr.entry_point,
                    ehdr.ph_offset,
                    ehdr.sh_offset,
                    ehdr.flags,
                    ehdr.header_size,
                    ehdr.ph_entry_size,
                    ehdr.ph_entry_count,
                    ehdr.sh_entry_size,
                    ehdr.sh_entry_count,
                    ehdr.sh_str_tab_index,
                ),
            ) = tuple((
                u16(self.endianness), // type
                u16(self.endianness), // machine
                u32(self.endianness), // version
                self.off_or_addr(),   // entry
                self.off_or_addr(),   // ph_offset
                self.off_or_addr(),   // sh_offset
                u32(self.endianness), // flags
                u16(self.endianness), // header_size,
                u16(self.endianness), // ph_entry_size
                u16(self.endianness), // ph_entry_count
                u16(self.endianness), // sh_entry_size
                u16(self.endianness), // sh_entry_count
                u16(self.endianness), // sh_str_table_index
            ))(input)?;

            Ok((remainder, ehdr))
        }
    }

    fn parse_shdr(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Shdr> + '_ {
        move |input: &[u8]| {
            let remainder: &[u8];
            let mut shdr = Shdr::default();
            (
                remainder,
                (
                    shdr.name,
                    shdr.type_,
                    shdr.flags,
                    shdr.addr,
                    shdr.offset,
                    shdr.size,
                    shdr.link,
                    shdr.info,
                    _,
                    shdr.entry_size,
                ),
            ) = tuple((
                u32(self.endianness), // name
                u32(self.endianness), // type
                self.off_or_addr(),   // flags
                self.off_or_addr(),   // addr
                self.off_or_addr(),   // offset
                self.off_or_addr(),   // size
                u32(self.endianness), // link
                u32(self.endianness), // info
                self.off_or_addr(),   // align
                self.off_or_addr(),   // entry_size
            ))(input)?;

            Ok((remainder, shdr))
        }
    }

    fn parse_phdr(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Phdr> + '_ {
        move |input: &[u8]| match self.class {
            Class::Elf32 => self.parse_phdr32()(input),
            Class::Elf64 => self.parse_phdr64()(input),
        }
    }

    fn parse_phdr32(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Phdr> + '_ {
        move |input: &[u8]| {
            let remainder: &[u8];
            let mut phdr = Phdr::default();
            (
                remainder,
                (
                    phdr.type_,
                    phdr.offset,
                    phdr.virt_addr,
                    phdr.phys_addr,
                    phdr.file_size,
                    phdr.mem_size,
                    phdr.flags,
                    phdr.alignment,
                ),
            ) = tuple((
                u32(self.endianness),                    // type_
                map(u32(self.endianness), |v| v.into()), // offset
                map(u32(self.endianness), |v| v.into()), // virt_addr
                map(u32(self.endianness), |v| v.into()), // phys_addr
                map(u32(self.endianness), |v| v.into()), // file_size
                map(u32(self.endianness), |v| v.into()), // mem_size
                u32(self.endianness),                    // flags
                map(u32(self.endianness), |v| v.into()), // alignment
            ))(input)?;

            Ok((remainder, phdr))
        }
    }

    fn parse_phdr64(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Phdr> + '_ {
        move |input: &[u8]| {
            let remainder: &[u8];
            let mut phdr = Phdr::default();
            (
                remainder,
                (
                    phdr.type_,
                    phdr.flags,
                    phdr.offset,
                    phdr.virt_addr,
                    phdr.phys_addr,
                    phdr.file_size,
                    phdr.mem_size,
                    phdr.alignment,
                ),
            ) = tuple((
                u32(self.endianness), // type_
                u32(self.endianness), // flags
                u64(self.endianness), // offset
                u64(self.endianness), // virt_addr
                u64(self.endianness), // phys_addr
                u64(self.endianness), // file_size
                u64(self.endianness), // mem_size
                u64(self.endianness), // alignment
            ))(input)?;

            Ok((remainder, phdr))
        }
    }

    /// Parses a symbol table from a section that matches a predicate.
    ///
    /// This function receives the ELF data together with a slice of [`Shdr`]
    /// structures that describe the sections in the ELF. The first section for
    /// which the predicate functions returns true is considered as symbol
    /// table and parsed accordingly. The result is a vector of [`elf::Sym`]
    /// structures.
    fn parse_sym_table<P>(
        &self,
        elf: &[u8],
        sections: &[Shdr],
        predicate: P,
    ) -> Vec<elf::Sym>
    where
        P: FnMut(&&Shdr) -> bool,
    {
        let mut result = vec![];

        if let Some(symtab) = sections.iter().find(predicate) {
            if let Some(range) = symtab.offset_range() {
                if let Some(data) = elf.get(range) {
                    let syms = many0(self.parse_sym())
                        .parse(data)
                        .map(|(_, syms)| syms)
                        .ok();

                    let symtabstr = sections.get(symtab.link as usize);

                    for s in syms.iter().flatten() {
                        let mut sym = elf::Sym::new();
                        sym.name = Self::parse_name(elf, symtabstr, s.name);
                        sym.value = Some(s.value);
                        sym.size = Some(s.size);
                        sym.shndx = Some(s.shndx.into());

                        sym.type_ =
                            Some(EnumOrUnknown::<elf::SymType>::from_i32(
                                (s.info & 0x0f) as i32,
                            ));

                        sym.bind =
                            Some(EnumOrUnknown::<elf::SymBind>::from_i32(
                                (s.info >> 4) as i32,
                            ));

                        sym.visibility = Some(EnumOrUnknown::<
                            elf::SymVisibility,
                        >::from_i32(
                            (s.other & 0x03) as i32
                        ));

                        result.push(sym);
                    }
                }
            }
        }

        result
    }

    fn parse_sym(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Sym> + '_ {
        move |input: &[u8]| match self.class {
            Class::Elf32 => self.parse_sym32()(input),
            Class::Elf64 => self.parse_sym64()(input),
        }
    }

    fn parse_sym32(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Sym> + '_ {
        move |input: &[u8]| {
            let remainder: &[u8];
            let mut sym = Sym::default();
            (
                remainder,
                (
                    sym.name, sym.value, sym.size, sym.info, sym.other,
                    sym.shndx,
                ),
            ) = tuple((
                u32(self.endianness),                    // name
                map(u32(self.endianness), |v| v.into()), // value
                map(u32(self.endianness), |v| v.into()), // size
                u8,                                      // info
                u8,                                      // other
                u16(self.endianness),                    // shndx
            ))(input)?;

            Ok((remainder, sym))
        }
    }

    fn parse_sym64(&self) -> impl FnMut(&[u8]) -> IResult<&[u8], Sym> + '_ {
        move |input: &[u8]| {
            let remainder: &[u8];
            let mut sym = Sym::default();
            (
                remainder,
                (
                    sym.name, sym.info, sym.other, sym.shndx, sym.value,
                    sym.size,
                ),
            ) = tuple((
                u32(self.endianness), // name
                u8,                   // info
                u8,                   // other
                u16(self.endianness), // shndx
                u64(self.endianness), // value
                u64(self.endianness), // size
            ))(input)?;

            Ok((remainder, sym))
        }
    }

    /// Given the raw data for an ELF file, some [`Shdr`] structure that
    /// describes a section containing a string table, and the index of
    /// some string within the string table, returns the string.
    fn parse_name(
        elf: &[u8],
        str_table: Option<&Shdr>,
        str_idx: u32,
    ) -> Option<String> {
        // Strictly speaking, the string table size is determined by the size
        // field in the `Shdr` structure. However, we don't use that field for
        // computing the string table size, and use all the data from the offset
        // indicated in `Shdr` until the end of the ELF file. Some files, like
        // 71adb87ee8ee76f32f54c70584ef14f67a4bc6f55df3f847c344726405927a1e
        // have an invalid size in `Shdr` even though they have a perfectly
        // valid string table.
        let str_table = match elf.get(str_table?.offset as usize..elf.len()) {
            Some(data) => data,
            None => return None,
        };
        // Take `str_idx` bytes from `section` and from the remaining bytes
        // read the string until the null terminator is found.
        let (_, (_, str_bytes)) =
            take::<u32, &[u8], nom::error::Error<&[u8]>>(str_idx)
                .and(take_till(|c| c == 0))
                .parse(str_table)
                .ok()?;

        Some(String::from_utf8_lossy(str_bytes).to_string())
    }

    fn parse_dyn_entries(&self, elf: &[u8], s: &Phdr) -> Vec<elf::Dyn> {
        let mut result = vec![];

        if let Some(range) = s.offset_range() {
            if let Some(segment_data) = elf.get(range) {
                // Parse tuples (tag, value) until the final marker
                // with tag == ELF_DT_NULL is found.
                let parser_result = many0(verify(
                    tuple((
                        // tag (a.k.a type)
                        self.off_or_addr(),
                        // value
                        self.off_or_addr(),
                    )),
                    |(tag, _)| *tag != Self::ELF_DT_NULL,
                ))
                .parse(segment_data);

                if let Ok((_, tuples)) = parser_result {
                    for (tag, value) in tuples {
                        let mut dyn_entry = elf::Dyn::new();
                        dyn_entry.type_ = tag
                            .try_into()
                            .ok()
                            .map(EnumOrUnknown::<elf::DynType>::from_i32);
                        dyn_entry.val = Some(value);
                        result.push(dyn_entry);
                    }
                }
            }
        }

        result
    }
}

/// ELF executable header.
#[derive(Default)]
struct Ehdr {
    type_: u16,
    machine: u16,
    version: u32,
    entry_point: u64,
    flags: u32,
    header_size: u16,
    sh_str_tab_index: u16,
    ph_offset: u64,
    ph_entry_size: u16,
    ph_entry_count: u16,
    sh_offset: u64,
    sh_entry_size: u16,
    sh_entry_count: u16,
}

/// ELF section header
#[derive(Default)]
struct Shdr {
    name: u32,
    type_: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entry_size: u64,
}

impl Shdr {
    /// Returns the range that occupies the section within the ELF file.
    pub fn offset_range(&self) -> Option<Range<usize>> {
        Some(
            self.offset as usize..self.offset.checked_add(self.size)? as usize,
        )
    }

    /// Returns the section's address range.
    pub fn addr_range(&self) -> Option<Range<u64>> {
        Some(self.addr..self.addr.checked_add(self.size)?)
    }
}

/// ELF program header
#[derive(Default)]
struct Phdr {
    type_: u32,
    flags: u32,
    offset: u64,
    virt_addr: u64,
    phys_addr: u64,
    file_size: u64,
    mem_size: u64,
    alignment: u64,
}

impl Phdr {
    /// Returns the range that occupies the segment within the ELF file.
    pub fn offset_range(&self) -> Option<Range<usize>> {
        Some(
            self.offset as usize
                ..self.offset.checked_add(self.file_size)? as usize,
        )
    }

    /// Returns the segment's virtual address range.
    pub fn virt_addr_range(&self) -> Option<Range<u64>> {
        Some(self.virt_addr..self.virt_addr.checked_add(self.mem_size)?)
    }
}

/// ELF symbol
#[derive(Default)]
struct Sym {
    name: u32,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    shndx: u16,
}
