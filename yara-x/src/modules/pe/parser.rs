use std::cell::OnceCell;
use std::cmp::min;
use std::collections::VecDeque;
use std::iter::zip;
use std::str::FromStr;

use bstr::{BStr, ByteSlice};
use byteorder::{ByteOrder, LE};
use memchr::memmem;
use nom::bytes::complete::{take, take_till};
use nom::combinator::{cond, map, verify};
use nom::error::ErrorKind;
use nom::multi::{count, length_data, many0};
use nom::number::complete::{le_u16, le_u32, le_u64, u8};
use nom::sequence::tuple;
use nom::{Err, IResult};
use protobuf::{EnumOrUnknown, MessageField};

use crate::modules::protos::pe;

type Error<'a> = nom::error::Error<&'a [u8]>;

/// Object that represents a [`PE`] file.
#[derive(Default)]
pub struct PE<'a> {
    /// Slice that contains the whole PE, from the DOS header to the end.
    data: &'a [u8],

    /// Subslice of `data`, that goes from the DOS header to the start of
    /// the PE header.
    dos_stub: &'a [u8],

    /// Subslice of `data` that goes from the start of the PE directory table
    /// to the end of the file.
    directory: &'a [u8],

    /// PE sections.
    sections: Vec<Section<'a>>,

    /// PE resources. Resources are parsed lazily when [`PE::get_resources`]
    /// is called for the first time.
    resources: OnceCell<Option<Vec<Resource<'a>>>>,

    /// PE directory entries. Directory entries are parsed lazily when
    /// [`PE::get_dir_entries`] is called for the first time.
    dir_entries: OnceCell<Option<Vec<DirEntry>>>,

    /// DOS header already parsed.
    pub dos_hdr: DOSHeader,

    /// PE header already parsed.
    pub pe_hdr: PEHeader,

    /// PE optional header already parsed.
    pub optional_hdr: OptionalHeader,
}

impl<'a> PE<'a> {
    /// Given the content of PE file, parses it and returns a [`PE`] object
    /// representing the file.
    pub fn parse(input: &'a [u8]) -> Result<Self, Err<Error<'a>>> {
        // Parse the MZ header.
        let (_, dos_hdr) = Self::parse_dos_header()(input)?;

        // The PE header starts at the offset indicated by `dos_hdr.e_lfanew`.
        // Everything between offset 0 and `dos_hdr.e_lfanew` is stored in the
        // `dos_stub` slice, including the DOS header, the MS-DOS stub and the
        // rich signature.
        let (pe, dos_stub) = take(dos_hdr.e_lfanew)(input)?;

        // Parse the PE header (IMAGE_FILE_HEADER)
        let (optional_hdr, pe_hdr) = Self::parse_pe_header()(pe)?;

        // Parse the PE optional header (IMAGE_OPTIONAL_HEADER).
        let (directory, optional_hdr) =
            Self::parse_opt_header()(optional_hdr)?;

        // The string table is located right after the COFF symbol table.
        let string_table_offset = pe_hdr.symbol_table_offset.saturating_add(
            pe_hdr.number_of_symbols.saturating_mul(Self::SIZE_OF_SYMBOL),
        );

        let string_table = input.get(string_table_offset as usize..);

        // Parse the section table. The section table is located right after
        // NT headers, which starts at pe_hdr and is composed of a the PE
        // signature, the file header, and a variable-length optional header.
        let sections = if let Some(section_table) = pe.get(
            Self::SIZE_OF_PE_SIGNATURE
                + Self::SIZE_OF_FILE_HEADER
                + pe_hdr.size_of_optional_header as usize..,
        ) {
            count(
                Self::parse_section(string_table),
                // The number of sections is capped to MAX_PE_SECTIONS.
                usize::min(
                    pe_hdr.number_of_sections as usize,
                    Self::MAX_PE_SECTIONS,
                ),
            )(section_table)
            .map(|(_, sections)| sections)
            .ok()
        } else {
            None
        };

        Ok(PE {
            data: input,
            sections: sections.unwrap_or_default(),
            resources: OnceCell::default(),
            dir_entries: OnceCell::default(),
            dos_hdr,
            pe_hdr,
            optional_hdr,
            dos_stub,
            directory,
        })
    }

    /// Convert a relative virtual address (RVA) to a file offset.
    ///
    /// A RVA is an offset relative to the base address of the executable
    /// program. The PE format uses RVAs in multiple places and sometimes
    /// is necessary to covert the RVA to a file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        // Find the RVA for the section with the lowest RVA.
        let lowest_section_rva = self
            .sections
            .iter()
            .map(|section| section.virtual_address)
            .min()
            .unwrap_or(0);

        // The target RVA is lower than the RVA of all sections, in such
        // cases the RVA is directly mapped to a file offset.
        if rva < lowest_section_rva {
            return Some(rva);
        }

        let mut section_rva = 0;
        let mut section_offset = 0;
        let mut section_raw_size = 0;

        // Find the section that contains the target RVA. If there are multiple
        // sections that may contain the RVA, the
        for s in self.sections.iter() {
            let size = if s.virtual_size != 0 {
                s.virtual_size
            } else {
                s.raw_data_size
            };

            let start = s.virtual_address;
            let end = start.saturating_add(size);

            // Check if the target RVA is within the boundaries of this
            // section, but only update `section_rva` with values
            // that are higher than the current one.
            if section_rva <= s.virtual_address && (start..end).contains(&rva)
            {
                section_rva = s.virtual_address;
                section_offset = s.raw_data_offset;
                section_raw_size = s.raw_data_size;

                // Round section_offset down to a multiple of 0x200.
                //
                // Rounding everything less than 0x200 to 0 as discussed in
                // https://code.google.com/archive/p/corkami/wikis/PE.wiki#PointerToRawData
                // does not work for PE32_FILE from the test suite and for
                // some tinype samples where File Alignment = 4
                // (http://www.phreedom.org/research/tinype/).
                //
                // If FileAlignment is >= 0x200, it is apparently ignored (see
                // Ero Carreras's pefile.py, PE.adjust_FileAlignment).
                let alignment = min(self.optional_hdr.file_alignment, 0x200);

                if let Some(rem) = section_offset.checked_rem(alignment) {
                    section_offset -= rem;
                }

                // TODO
                //if self.optional_hdr.section_alignment >= 0x1000 {
                //  todo!()
                //}
            }
        }

        // PE sections can have a raw (on disk) size smaller than their
        // in-memory size. In such cases, even though the RVA lays within
        // the boundaries of the section while in memory, the RVA doesn't
        // have an associated file offset.
        if rva.saturating_sub(section_rva) >= section_raw_size {
            return None;
        }

        let result = section_offset + rva - section_rva;

        // Make sure the resulting offset is within the file.
        if result as usize >= self.data.len() {
            return None;
        }

        Some(result)
    }

    /// Returns a slice of [`Section`] structures, one per each section
    /// declared in the PE file.
    ///
    /// Sections appear in the same order as they are in the section table.
    pub fn get_sections(&self) -> &[Section] {
        self.sections.as_slice()
    }

    /// Returns information about the rich header.
    ///
    /// The rich header is an undocumented chunk of data found between the DOS
    /// and the PE headers. It's not a standardized part of the PE file format
    /// but rather a series of undocumented values placed by some Microsoft
    /// compilers, which contain information about the toolchain that produced
    /// the PE file.
    ///
    /// More info:
    ///
    /// http://www.ntcore.com/files/richsign.htm
    /// https://bytepointer.com/articles/the_microsoft_rich_header.htm
    pub fn get_rich_header(&self) -> Option<RichHeader> {
        let (_, rich_header) =
            Self::parse_rich_header()(self.dos_stub).ok()?;
        Some(rich_header)
    }

    /// Returns a slice of [`Resource`] structures, one per each resource
    /// declared in the PE file.
    pub fn get_resources(&self) -> &[Resource<'a>] {
        // Resources are parsed only the first time this function is called,
        // in subsequent calls the already parsed resources are returned.
        self.resources
            .get_or_init(|| self.parse_resources())
            .as_deref()
            .unwrap_or_default()
    }

    /// Returns the entries found in the PE directory table.
    ///
    /// The number of entries is limited MAX_DIR_ENTRIES (16), which is the
    /// maximum number of directory entries according to the PE specification.
    /// Some PE files may a `number_of_rva_and_sizes` larger than 16, but this
    /// function ignores the extra entries.
    pub fn get_dir_entries(&self) -> &[DirEntry] {
        // Resources are parsed only the first time this function is called,
        // in subsequent calls the already parsed resources are returned.
        self.dir_entries
            .get_or_init(|| self.parse_dir_entries())
            .as_deref()
            .unwrap_or_default()
    }

    /// Returns the data associated to a given directory entry.
    ///
    /// Each directory entry has a RVA and a size. This function translates the
    /// RVA into a file offset and returns the chunk of file that starts at
    /// that offset and has the size indicated by the directory entry.
    ///
    /// Returns `None` if the PE is corrupted in some way that prevents the
    /// data from being found.
    pub fn get_dir_entry_data(&self, index: usize) -> Option<&'a [u8]> {
        // Nobody should call this function with an index greater
        // than MAX_DIR_ENTRIES.
        debug_assert!(index < Self::MAX_DIR_ENTRIES);

        // In theory, `index` should be be lower than
        // `number_of_rva_and_sizes`, but we don't enforce it because some PE
        // files have a `number_of_rva_and_sizes` values lower than the actual
        // number of directory entries. For example, the .NET file
        // 7ff1bf680c80fd73c0b35084904848b3705480ddeb6d0eff62180bd14cd18570
        // has `number_of_rva_and_sizes` set to 11, but it has a valid
        // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR entry (index = 14). If we are
        // overly strict here and only parse entries which are less than
        // `number_of_rva_and_sizes` we run the risk of missing otherwise
        // perfectly valid files.

        let dir_entry = self
            .directory
            .get(index * Self::SIZE_OF_DIR_ENTRY..)
            .and_then(|entry| Self::parse_dir_entry()(entry).ok())
            .map(|(_reminder, entry)| entry)?;

        let start = self.rva_to_offset(dir_entry.addr)? as usize;
        let end = min(
            self.data.len(),
            start.saturating_add(dir_entry.size as usize),
        );

        self.data.get(start..end)
    }
}

impl<'a> PE<'a> {
    const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
    const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

    const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;

    const RICH_TAG: &'static [u8] = &[0x52_u8, 0x69, 0x63, 0x68];
    const DANS_TAG: &'static [u8] = &[0x44_u8, 0x61, 0x6e, 0x53];

    const SIZE_OF_PE_SIGNATURE: usize = 4; // size of PE signature (PE\0\0).
    const SIZE_OF_FILE_HEADER: usize = 20; // size of IMAGE_FILE_HEADER
    const SIZE_OF_DIR_ENTRY: usize = 8;
    const SIZE_OF_SYMBOL: u32 = 18;

    const MAX_PE_SECTIONS: usize = 96;
    const MAX_DIR_ENTRIES: usize = 16;

    fn parse_dos_header() -> impl FnMut(&[u8]) -> IResult<&[u8], DOSHeader> {
        move |input: &[u8]| {
            let mut dos_hdr = DOSHeader::default();
            let remainder;

            (
                remainder,
                (
                    dos_hdr.e_magic,    // DOS magic.
                    dos_hdr.e_cblp,     // Bytes on last page of file
                    dos_hdr.e_cp,       // Pages in file
                    dos_hdr.e_crlc,     // Relocations
                    dos_hdr.e_cparhdr,  // Size of header in paragraphs
                    dos_hdr.e_minalloc, // Minimum extra paragraphs needed
                    dos_hdr.e_maxalloc, // Maximum extra paragraphs needed
                    dos_hdr.e_ss,       // Initial (relative) SS value
                    dos_hdr.e_sp,       // Initial SP value
                    dos_hdr.e_csum,     // Checksum
                    dos_hdr.e_ip,       // Initial IP value
                    dos_hdr.e_cs,       // Initial (relative) CS value
                    dos_hdr.e_lfarlc,   // File address of relocation table
                    dos_hdr.e_ovno,     // Overlay number
                    _,                  // Reserved words
                    dos_hdr.e_oemid,    // OEM identifier (for e_oeminfo)
                    dos_hdr.e_oeminfo,  // OEM information; e_oemid specific
                    _,                  // Reserved words
                    dos_hdr.e_lfanew,   // File address of new exe header
                ),
            ) = tuple((
                // Magic must be 'MZ'
                verify(le_u16, |magic| *magic == 0x5A4D),
                le_u16,            // e_cblp
                le_u16,            // e_cp
                le_u16,            // e_crlc
                le_u16,            // e_cparhdr
                le_u16,            // e_minalloc
                le_u16,            // e_maxalloc
                le_u16,            // e_ss
                le_u16,            // e_sp
                le_u16,            // e_csum
                le_u16,            // e_ip
                le_u16,            // e_cs
                le_u16,            // e_lfarlc
                le_u16,            // e_ovno
                count(le_u16, 4),  // e_res
                le_u16,            // e_oemid
                le_u16,            // e_oeminfo
                count(le_u16, 10), // e_res2
                le_u32,            // e_lfanew
            ))(input)?;

            Ok((remainder, dos_hdr))
        }
    }

    fn parse_pe_header() -> impl FnMut(&[u8]) -> IResult<&[u8], PEHeader> {
        move |input: &[u8]| {
            let mut pe_hdr = PEHeader::default();
            let remainder;

            (
                remainder,
                (
                    _, // magic
                    pe_hdr.machine,
                    pe_hdr.number_of_sections,
                    pe_hdr.timestamp,
                    pe_hdr.symbol_table_offset,
                    pe_hdr.number_of_symbols,
                    pe_hdr.size_of_optional_header,
                    pe_hdr.characteristics,
                ),
            ) = tuple((
                // Magic must be 'PE\0\0'
                verify(le_u32, |magic| *magic == 0x00004550),
                le_u16, // machine
                le_u16, // number_of_sections
                le_u32, // timestamp
                le_u32, // ptr_sym_table
                le_u32, // number_of_symbols
                le_u16, // size_of_optional_header
                le_u16, // characteristics
            ))(input)?;

            Ok((remainder, pe_hdr))
        }
    }

    fn parse_opt_header() -> impl FnMut(&[u8]) -> IResult<&[u8], OptionalHeader>
    {
        move |input: &[u8]| {
            let mut opt_hdr = OptionalHeader::default();
            let magic;
            let base_of_data: Option<u32>;
            let image_base32: Option<u32>;
            let image_base64: Option<u64>;
            let mut remainder;

            (
                remainder,
                (
                    magic,
                    opt_hdr.major_linker_version,
                    opt_hdr.minor_linker_version,
                    opt_hdr.size_of_code,
                    opt_hdr.size_of_initialized_data,
                    opt_hdr.size_of_uninitialized_data,
                    opt_hdr.entry_point,
                    opt_hdr.base_of_code,
                ),
            ) = tuple((
                verify(le_u16, |magic| {
                    *magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC
                        || *magic == Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC
                }),
                u8,     // major_linker_ver
                u8,     // minor_linker_ver
                le_u32, // size_of_code
                le_u32, // size_of_initialized_data
                le_u32, // size_of_uninitialized_data
                le_u32, // entry_point
                le_u32, // base_of_code
            ))(input)?;

            (
                remainder,
                (
                    base_of_data, // only in 32-bits PE
                    image_base32, // only in 32-bits PE
                    image_base64, // only in 64-bits PE
                ),
            ) = tuple((
                cond(magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC, le_u32),
                cond(magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC, le_u32),
                cond(magic == Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC, le_u64),
            ))(remainder)?;

            opt_hdr.base_of_data = base_of_data;
            opt_hdr.image_base =
                image_base64.or(image_base32.map(|i| i as u64));

            (
                remainder,
                (
                    opt_hdr.section_alignment,
                    opt_hdr.file_alignment,
                    opt_hdr.major_os_version,
                    opt_hdr.minor_os_version,
                    opt_hdr.major_image_version,
                    opt_hdr.minor_image_version,
                    opt_hdr.major_subsystem_version,
                    opt_hdr.minor_subsystem_version,
                    opt_hdr.win32_version,
                    opt_hdr.size_of_image,
                    opt_hdr.size_of_headers,
                    opt_hdr.checksum,
                    opt_hdr.subsystem,
                    opt_hdr.dll_characteristics,
                    opt_hdr.size_of_stack_reserve,
                    opt_hdr.size_of_stack_commit,
                    opt_hdr.size_of_heap_reserve,
                    opt_hdr.size_of_heap_commit,
                    opt_hdr.loader_flags,
                    opt_hdr.number_of_rva_and_sizes,
                ),
            ) = tuple((
                le_u32, // section_alignment
                le_u32, // file_alignment
                le_u16, // major_os_version
                le_u16, // minor_os_version
                le_u16, // major_image_version
                le_u16, // minor_image_version
                le_u16, // major_subsystem_version
                le_u16, // minor_subsystem_version
                le_u32, // win32_version
                le_u32, // size_of_image
                le_u32, // size_of_headers
                le_u32, // checksum
                le_u16, // subsystem
                le_u16, // dll_characteristics
                uint(magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
                uint(magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
                uint(magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
                uint(magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
                le_u32, // loader_flags
                le_u32, // number_of_rva_and_sizes
            ))(remainder)?;

            Ok((remainder, opt_hdr))
        }
    }

    fn parse_rich_header() -> impl FnMut(&[u8]) -> IResult<&[u8], RichHeader> {
        move |input: &[u8]| {
            // Search for the "Rich" tag that indicates the end of the rich
            // data. The tag is searched starting at the end of the input and
            // going backwards.
            let rich_tag_pos = memmem::rfind(input, Self::RICH_TAG)
                .ok_or(Err::Error(Error::new(input, ErrorKind::Tag)))?;

            // The u32 that follows the "Rich" tag is the XOR key used for
            // for encrypting the Rich data.
            let (remainder, key) = le_u32(&input[rich_tag_pos + 4..])?;

            // Search for the "DanS" tag that indicates the start of the rich
            // data. This tag is encrypted with the XOR key.
            let dans_tag = key ^ LE::read_u32(Self::DANS_TAG);

            let dans_tag_pos = memmem::rfind(
                &input[..rich_tag_pos],
                dans_tag.to_le_bytes().as_slice(),
            )
            .ok_or(Err::Error(Error::new(
                &input[..rich_tag_pos],
                ErrorKind::Tag,
            )))?;

            let raw_data = &input[dans_tag_pos..rich_tag_pos];
            let mut clear_data = raw_data.to_owned();

            // Decrypt the rich data by XORing each byte in the data with
            // the byte corresponding byte in the key.
            for (data_byte, key_byte) in
                zip(clear_data.iter_mut(), key.to_le_bytes().iter().cycle())
            {
                *data_byte ^= key_byte;
            }

            // Parse the rich data.
            let (_, (_dans, _padding, tools)) =
                tuple((
                    le_u32::<&[u8], Error>,
                    take(12_usize),
                    many0(tuple((le_u16, le_u16, le_u32))),
                ))(clear_data.as_slice())
                .unwrap_or_default();

            let rich_header = RichHeader {
                offset: dans_tag_pos,
                key,
                raw_data,
                clear_data,
                tools,
            };

            Ok((remainder, rich_header))
        }
    }

    fn parse_section(
        string_table: Option<&'a [u8]>,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Section> {
        move |input: &'a [u8]| {
            let mut section = Section::default();
            let remainder;

            (
                remainder,
                (
                    section.name,
                    section.virtual_size,
                    section.virtual_address,
                    section.raw_data_size,
                    section.raw_data_offset,
                    section.pointer_to_relocations,
                    section.pointer_to_line_numbers,
                    section.number_of_relocations,
                    section.number_of_line_numbers,
                    section.characteristics,
                ),
            ) = tuple((
                map(take(8_usize), |name| {
                    // The PE specification states that:
                    //
                    // "Section name is an 8-byte, null-padded UTF-8 encoded
                    // string. If the string is exactly 8 characters long,
                    // there is no terminating null.".
                    //
                    // Here we remove the trailing nulls, if any, but don't
                    // assume that the name is valid UTF-8 because some files
                    // have section names containing zeroes or non-valid UTF-8.
                    // For example, the file listed below has sections named
                    // ".data\x00l\x06" and ".bss\x00\x7f".
                    //
                    // 0043812838495a45449a0ac61a81b9c16eddca1ad249fb4f7fdb1c4505e9bb34
                    //
                    BStr::new(name).trim_end_with(|c| c == '\0').into()
                }), // name
                le_u32, // virtual_size
                le_u32, // virtual_address
                le_u32, // raw_data_size
                le_u32, // raw_data_offset
                le_u32, // pointer_to_relocations
                le_u32, // pointer_to_line_numbers
                le_u16, // number_of_relocations
                le_u16, // number_of_line_numbers
                le_u32, // characteristics
            ))(input)?;

            // Certain PE files produced by GNU compilers may contain section
            // name following the pattern of "/d+" (for example: "/4", "/10",
            // "/234").In such instances, the number after the slash denotes an
            // offset within the string table where the actual section name is
            // stored. This approach allows the inclusion of section names
            // longer than the 8 bytes allocated in the PE section table. For
            // example, the file listed below contains a section named "/4",
            // which gets translated into ".gnu_debuglink".
            //
            // 2e9c671b8a0411f2b397544b368c44d7f095eb395779de0ad1ac946914dfa34c
            //
            if let Some(string_table) = string_table {
                if let Some(offset) = section
                    .name
                    .to_str()
                    .ok()
                    .and_then(|name| name.strip_prefix('/'))
                    .and_then(|offset| u32::from_str(offset).ok())
                {
                    if let Some(s) = string_table.get(offset as usize..) {
                        if let Ok((_, s)) =
                            take_till::<_, &[u8], Error>(|c| c == 0)(s)
                        {
                            section.full_name = Some(BStr::new(s));
                        }
                    }
                }
            }

            Ok((remainder, section))
        }
    }

    fn parse_dir_entry() -> impl FnMut(&[u8]) -> IResult<&[u8], DirEntry> {
        move |input: &[u8]| {
            map(tuple((le_u32, le_u32)), |(addr, size)| DirEntry {
                addr,
                size,
            })(input)
        }
    }

    fn parse_rsrc_dir() -> impl FnMut(&[u8]) -> IResult<&[u8], usize> {
        move |input: &[u8]| {
            let (
                remainder,
                (
                    characteristics,
                    timestamp,
                    major_version,
                    minor_version,
                    number_of_named_entries,
                    number_of_id_entries,
                ),
            ) = tuple((
                le_u32::<&[u8], Error>, // characteristics
                le_u32,                 // timestamp
                le_u16,                 // major_version
                le_u16,                 // minor_version
                le_u16,                 // number_of_named_entries
                le_u16,                 // number_of_id_entries
            ))(input)?;

            Ok((
                remainder,
                number_of_id_entries as usize
                    + number_of_named_entries as usize,
            ))
        }
    }

    fn parse_rsrc_dir_entry(
        resource_section: &'a [u8],
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ResourceDirEntry> {
        move |input: &'a [u8]| {
            let (remainder, (name_or_id, mut offset)) = tuple((
                le_u32, // name_or_id
                le_u32, // offset
            ))(input)?;

            // If the high bit of `name_or_id` is set, then the remaining bits
            // are the offset within the resource section where the resource
            // name is found. The name is a UTF-16LE string that starts with a
            // u16 containing its length in characters. If the high bit is not
            // set then `name_or_id` is just the resource ID.
            let id = if name_or_id & 0x80000000 != 0 {
                resource_section
                    .get((name_or_id & 0x7FFFFFFF) as usize..)
                    .and_then(|string| {
                        length_data(map(
                            le_u16::<&[u8], Error>,
                            |len| len * 2, //  length from characters to bytes
                        ))(string)
                        .map(|(_, s)| s)
                        .ok()
                    })
                    .map(ResourceId::Name)
                    .unwrap_or(ResourceId::Unknown)
            } else {
                ResourceId::Id(name_or_id)
            };

            // If the high bit of `offset` is set, this entry corresponds to a
            // subdirectory. In that case clear the high bit to get the actual
            // offset.
            let is_subdir = if offset & 0x80000000 != 0 {
                offset &= 0x7FFFFFFF;
                true
            } else {
                false
            };

            Ok((remainder, ResourceDirEntry { is_subdir, id, offset }))
        }
    }

    fn parse_rsrc_entry() -> impl FnMut(&[u8]) -> IResult<&[u8], ResourceEntry>
    {
        move |input: &[u8]| {
            map(
                tuple((
                    le_u32, // offset
                    le_u32, // size
                    le_u32, // code_page
                    le_u32, // reserved
                )),
                |(offset, size, _code_page, _reserved)| ResourceEntry {
                    offset,
                    size,
                },
            )(input)
        }
    }

    fn parse_resources(&self) -> Option<Vec<Resource<'a>>> {
        let rsrc_section =
            self.get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_RESOURCE)?;

        // Resources are stored in tree structure with three levels. Non-leaf
        // nodes are represented by IMAGE_RESOURCE_DIRECTORY structures, where
        // the root of the tree is the IMAGE_RESOURCE_DIRECTORY located at the
        // point indicated by the IMAGE_DIRECTORY_ENTRY_RESOURCE entry in the
        // PE directory.
        //
        // Right after each IMAGE_RESOURCE_DIRECTORY, there's a sequence of
        // IMAGE_RESOURCE_DIRECTORY_ENTRY structures, where each of this
        // entries can correspond to leaf in the tree (i.e: an actual resource)
        // or a subdirectory.
        //
        // If the entry corresponds to a subdirectory, its offset points to
        // another IMAGE_RESOURCE_DIRECTORY structure, which in turns is
        // followed by more IMAGE_DIRECTORY_ENTRY_RESOURCE. If the entry
        // corresponds to leaf, its offset points to the resource data. The
        // structure of this data depends on the type of the resource. But we
        // don't parse the resource themselves, only the resource tree.
        //
        // This function performs a BFS traversal over the resource tree,
        // creating a list of resources with one entry per tree leaf. The
        // three levels in the tree correspond to resource types, resources,
        // and language. That means that at the top level we have one entry
        // per resource type: icon, string table, menu, etc. The children of
        // each type correspond to individual resources of that type, and
        // the children of each individual resource represent the resource in
        // a specific language.
        let mut queue = VecDeque::new();
        let mut resources = vec![];

        let ids = (
            ResourceId::Unknown, // type
            ResourceId::Unknown, // resource
            ResourceId::Unknown, // language
        );

        // We start by processing the root IMAGE_RESOURCE_DIRECTORY, located
        // at the very beginning of the resources section. The first item
        // in the tuple represents the tree level.
        queue.push_back((0, ids, rsrc_section));

        while let Some((level, ids, rsrc_dir)) = queue.pop_front() {
            // Parse the IMAGE_RESOURCE_DIRECTORY structure.
            let (raw_entries, num_entries) =
                match Self::parse_rsrc_dir()(rsrc_dir) {
                    Ok(result) => result,
                    Err(_) => continue,
                };

            // Parse a series of IMAGE_RESOURCE_DIRECTORY_ENTRY that come
            // right after the IMAGE_RESOURCE_DIRECTORY. The number of entries
            // is extracted from the IMAGE_RESOURCE_DIRECTORY structure.
            let dir_entries = count(
                Self::parse_rsrc_dir_entry(rsrc_section),
                num_entries,
            )(raw_entries)
            .map(|(_, dir_entries)| dir_entries);

            // Iterate over the directory entries. Each entry can be either a
            // subdirectory or a leaf.
            for dir_entry in dir_entries.iter().flatten() {
                if let Some(entry_data) =
                    rsrc_section.get(dir_entry.offset as usize..)
                {
                    let ids = match level {
                        // At level 0 each directory entry corresponds to a
                        // resource type. The specific resource and language
                        // are still unknown.
                        0 => (
                            dir_entry.id,        // type
                            ResourceId::Unknown, // resource
                            ResourceId::Unknown, // language
                        ),
                        // At level 1 each directory entry corresponds to an
                        // individual resource, the type is the one obtained
                        // from the parent, and the language is unknown.
                        1 => (ids.0, dir_entry.id, ResourceId::Unknown),
                        // At level 3 each directory entry corresponds to a
                        // language. The type ID and resource ID are the ones
                        // obtained from the parent.
                        2 => (ids.0, ids.1, dir_entry.id),
                        // Resource trees have 3 levels at most. We must
                        // protect ourselves against corrupted or maliciously
                        // crafted files that have too many levels.
                        _ => continue,
                    };

                    if dir_entry.is_subdir {
                        queue.push_back((level + 1, ids, entry_data));
                    } else if let Ok((_, rsrc_entry)) =
                        Self::parse_rsrc_entry()(entry_data)
                    {
                        resources.push(Resource {
                            type_id: ids.0,
                            rsrc_id: ids.1,
                            lang_id: ids.2,
                            // `rsrc_entry.offset` is relative to the start of
                            // the resource section, so it's actually a RVA.
                            // Here we convert it to a file offset.
                            offset: self.rva_to_offset(rsrc_entry.offset),
                            rva: rsrc_entry.offset,
                            length: rsrc_entry.size,
                        })
                    }
                }
            }
        }

        Some(resources)
    }

    fn parse_dir_entries(&self) -> Option<Vec<DirEntry>> {
        // The number of directory entries is limited to MAX_DIR_ENTRIES.
        let num_dir_entries = usize::max(
            self.optional_hdr.number_of_rva_and_sizes as usize,
            Self::MAX_DIR_ENTRIES,
        );

        // Parse the data directory.
        count(Self::parse_dir_entry(), num_dir_entries)(self.directory)
            .map(|(_, entries)| entries)
            .ok()
    }
}

impl From<PE<'_>> for pe::PE {
    fn from(pe: PE) -> Self {
        let mut result = pe::PE::new();

        result.is_pe = Some(true);
        result.machine = pe
            .pe_hdr
            .machine
            .try_into()
            .ok()
            .map(EnumOrUnknown::<pe::Machine>::from_i32);

        result.timestamp = Some(pe.pe_hdr.timestamp);
        result.characteristics = Some(pe.pe_hdr.characteristics.into());
        result.number_of_sections = Some(pe.pe_hdr.number_of_sections.into());
        result.pointer_to_symbol_table = Some(pe.pe_hdr.symbol_table_offset);
        result.number_of_symbols = Some(pe.pe_hdr.number_of_symbols);
        result.size_of_optional_header =
            Some(pe.pe_hdr.size_of_optional_header.into());

        result.size_of_code = Some(pe.optional_hdr.size_of_code);
        result.base_of_code = Some(pe.optional_hdr.base_of_code);
        result.base_of_data = pe.optional_hdr.base_of_data;
        result.entry_point_raw = Some(pe.optional_hdr.entry_point);
        result.section_alignment = Some(pe.optional_hdr.section_alignment);
        result.file_alignment = Some(pe.optional_hdr.file_alignment);
        // TODO
        //result.entry_point =
        result.loader_flags = Some(pe.optional_hdr.loader_flags);
        result.dll_characteristics =
            Some(pe.optional_hdr.dll_characteristics.into());
        result.checksum = Some(pe.optional_hdr.checksum);
        result.win32_version_value = Some(pe.optional_hdr.win32_version);

        result.size_of_stack_reserve =
            Some(pe.optional_hdr.size_of_stack_reserve);

        result.size_of_stack_commit =
            Some(pe.optional_hdr.size_of_stack_commit);

        result.size_of_heap_reserve =
            Some(pe.optional_hdr.size_of_heap_reserve);

        result.size_of_heap_commit = Some(pe.optional_hdr.size_of_heap_commit);

        result.number_of_rva_and_sizes =
            Some(pe.optional_hdr.number_of_rva_and_sizes);

        // TODO
        // number_of_version_infos
        // opthdr_magic

        result.image_base = pe.optional_hdr.image_base;

        result.size_of_image = Some(pe.optional_hdr.size_of_image);
        result.size_of_headers = Some(pe.optional_hdr.size_of_headers);

        result.size_of_initialized_data =
            Some(pe.optional_hdr.size_of_initialized_data);

        result.size_of_uninitialized_data =
            Some(pe.optional_hdr.size_of_uninitialized_data);

        result.linker_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_linker_version.into()),
            minor: Some(pe.optional_hdr.minor_linker_version.into()),
            special_fields: Default::default(),
        });

        result.os_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_os_version.into()),
            minor: Some(pe.optional_hdr.minor_os_version.into()),
            special_fields: Default::default(),
        });

        result.image_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_image_version.into()),
            minor: Some(pe.optional_hdr.minor_image_version.into()),
            special_fields: Default::default(),
        });

        result.subsystem_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_subsystem_version.into()),
            minor: Some(pe.optional_hdr.minor_subsystem_version.into()),
            special_fields: Default::default(),
        });

        result.subsystem = pe
            .optional_hdr
            .subsystem
            .try_into()
            .ok()
            .map(EnumOrUnknown::<pe::Subsystem>::from_i32);

        result.data_directories =
            pe.get_dir_entries().iter().map(pe::DirEntry::from).collect();

        result.sections =
            pe.get_sections().iter().map(pe::Section::from).collect();

        result.resources =
            pe.get_resources().iter().map(pe::Resource::from).collect();

        if let Some(rich_header) = pe.get_rich_header() {
            result.rich_signature = MessageField::some(pe::RichSignature {
                offset: Some(rich_header.offset.try_into().unwrap()),
                length: Some(rich_header.raw_data.len().try_into().unwrap()),
                key: Some(rich_header.key),
                // TODO: implement some mechanism for returning slices
                // backed by the scanned data without copy.
                raw_data: Some(rich_header.raw_data.to_vec()),
                clear_data: Some(rich_header.clear_data),
                tools: rich_header
                    .tools
                    .iter()
                    .map(|(version, toolid, times)| {
                        let mut entry = pe::RichTool::new();
                        entry.toolid = Some((*toolid).into());
                        entry.version = Some((*version).into());
                        entry.times = Some(*times);
                        entry
                    })
                    .collect(),
                special_fields: Default::default(),
            });
        }

        // The overlay offset is the offset where the last section ends. The
        // last section is not the last one in the section table, but the one
        // with the highest raw_data_offset + raw_data_size.
        let overlay_offset = result
            .sections
            .iter()
            .map(|section| {
                section.raw_data_offset.unwrap() as u64
                    + section.raw_data_size.unwrap() as u64
            })
            .max();

        let overlay_size = overlay_offset.and_then(|overlay_offset| {
            (pe.data.len() as u64).checked_sub(overlay_offset)
        });

        result.overlay =
            MessageField::some(match (overlay_offset, overlay_size) {
                (Some(offset), Some(size)) if size > 0 => pe::Overlay {
                    offset: Some(offset),
                    size: Some(size),
                    special_fields: Default::default(),
                },
                _ => pe::Overlay {
                    offset: Some(0),
                    size: Some(0),
                    special_fields: Default::default(),
                },
            });

        result
    }
}

#[derive(Default)]
pub struct DOSHeader {
    e_magic: u16,    // DOS magic.
    e_cblp: u16,     // Bytes on last page of file
    e_cp: u16,       // Pages in file
    e_crlc: u16,     // Relocations
    e_cparhdr: u16,  // Size of header in paragraphs
    e_minalloc: u16, // Minimum extra paragraphs needed
    e_maxalloc: u16, // Maximum extra paragraphs needed
    e_ss: u16,       // Initial (relative) SS value
    e_sp: u16,       // Initial SP value
    e_csum: u16,     // Checksum
    e_ip: u16,       // Initial IP value
    e_cs: u16,       // Initial (relative) CS value
    e_lfarlc: u16,   // File address of relocation table
    e_ovno: u16,     // Overlay number
    e_oemid: u16,    // OEM identifier (for e_oeminfo)
    e_oeminfo: u16,  // OEM information; e_oemid specific
    e_lfanew: u32,   // File address of new exe header
}

#[derive(Default)]
pub struct PEHeader {
    machine: u16,
    number_of_sections: u16,
    timestamp: u32,
    symbol_table_offset: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[derive(Default)]
pub struct OptionalHeader {
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    entry_point: u32,
    base_of_code: u32,
    base_of_data: Option<u32>,
    image_base: Option<u64>,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

pub struct RichHeader<'a> {
    offset: usize,
    key: u32,
    raw_data: &'a [u8],
    clear_data: Vec<u8>,
    tools: Vec<(u16, u16, u32)>,
}

#[derive(Default)]
pub struct Section<'a> {
    name: &'a BStr,
    full_name: Option<&'a BStr>,
    virtual_size: u32,
    virtual_address: u32,
    raw_data_size: u32,
    raw_data_offset: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

impl From<&Section<'_>> for pe::Section {
    fn from(value: &Section) -> Self {
        let mut sec = pe::Section::new();
        sec.name = Some(value.name.to_vec());
        sec.full_name = value
            .full_name
            .map(|name| name.to_vec())
            .or_else(|| sec.name.clone());
        sec.raw_data_size = Some(value.raw_data_size);
        sec.raw_data_offset = Some(value.raw_data_offset);
        sec.virtual_size = Some(value.virtual_size);
        sec.virtual_address = Some(value.virtual_address);
        sec.pointer_to_line_numbers = Some(value.pointer_to_line_numbers);
        sec.pointer_to_relocations = Some(value.pointer_to_relocations);
        sec.number_of_line_numbers = Some(value.number_of_line_numbers.into());
        sec.number_of_relocations = Some(value.number_of_relocations.into());
        sec.characteristics = Some(value.characteristics);
        sec
    }
}

pub struct DirEntry {
    addr: u32,
    size: u32,
}

impl From<&DirEntry> for pe::DirEntry {
    fn from(value: &DirEntry) -> Self {
        let mut entry = pe::DirEntry::new();
        entry.virtual_address = Some(value.addr);
        entry.size = Some(value.size);
        entry
    }
}

#[derive(Debug)]
pub struct ResourceDirEntry<'a> {
    /// True if this entry corresponds to a resource subdirectory.
    is_subdir: bool,
    /// Resource ID or name.
    id: ResourceId<'a>,
    /// Offset relative to the resources section where the data is found.
    offset: u32,
}

#[derive(Debug, Clone, Copy)]
enum ResourceId<'a> {
    Unknown,
    Id(u32),
    Name(&'a [u8]),
}

#[derive(Debug)]
pub struct ResourceEntry {
    /// Offset relative to the resources section where the data is found.
    offset: u32,
    size: u32,
}

/// Represents a resource in the PE.
pub struct Resource<'a> {
    rsrc_id: ResourceId<'a>,
    type_id: ResourceId<'a>,
    lang_id: ResourceId<'a>,
    offset: Option<u32>,
    length: u32,
    rva: u32,
}

impl From<&Resource<'_>> for pe::Resource {
    fn from(value: &Resource) -> Self {
        let mut resource = pe::Resource::new();
        resource.rva = Some(value.rva);
        resource.length = Some(value.length);
        resource.offset = value.offset;

        match value.type_id {
            ResourceId::Id(id) => {
                resource.type_ = id
                    .try_into()
                    .ok()
                    .map(EnumOrUnknown::<pe::ResourceType>::from_i32);
            }
            ResourceId::Name(name) => {
                resource.type_string = Some(name.to_vec())
            }
            _ => {}
        }

        match value.rsrc_id {
            ResourceId::Id(id) => resource.id = Some(id),
            ResourceId::Name(name) => {
                resource.name_string = Some(name.to_vec())
            }
            _ => {}
        }

        match value.lang_id {
            ResourceId::Id(id) => resource.language = Some(id),
            ResourceId::Name(name) => {
                resource.language_string = Some(name.to_vec())
            }
            _ => {}
        }

        resource
    }
}

/// Parser that reads a 32-bits or 64-bits unsigned integer, depending on
/// its argument. The result is always an `u64`.
fn uint(_32bits: bool) -> impl FnMut(&[u8]) -> IResult<&[u8], u64> {
    move |input: &[u8]| {
        if _32bits {
            let (remainder, i) = le_u32(input)?;
            Ok((remainder, i as u64))
        } else {
            le_u64(input)
        }
    }
}
