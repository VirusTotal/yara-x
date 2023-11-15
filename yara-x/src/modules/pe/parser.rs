use std::cell::OnceCell;
use std::cmp::min;
use std::collections::VecDeque;
use std::iter::zip;
use std::str::{from_utf8, FromStr};

use bstr::{BStr, ByteSlice};
use byteorder::{ByteOrder, LE};
use indexmap::IndexMap;
use memchr::memmem;
use nom::branch::{alt, permutation};
use nom::bytes::complete::{take, take_till};
use nom::combinator::{
    cond, consumed, fail, iterator, map, opt, success, verify,
};
use nom::error::ErrorKind;
use nom::multi::{count, fold_many1, length_data, many0, many1, many_m_n};
use nom::number::complete::{le_u16, le_u32, le_u64, u8};
use nom::sequence::tuple;
use nom::{Err, IResult, Parser, ToUsize};
use protobuf::{EnumOrUnknown, MessageField};

use crate::modules::protos::pe;

type Error<'a> = nom::error::Error<&'a [u8]>;

/// Represents a Windows Portable Executable (PE) file.
///
/// New instances of this type are created by parsing the content of a PE
/// file with the [`PE::parse`] function.
#[derive(Default)]
pub struct PE<'a> {
    /// Slice that contains the whole PE, from the DOS header to the end.
    data: &'a [u8],

    /// Subslice of `data`, that goes from the DOS header to the start of
    /// the PE header.
    dos_stub: &'a [u8],

    /// Rich header
    rich_header: OnceCell<Option<RichHeader<'a>>>,

    /// Subslice of `data` that goes from the start of the PE directory table
    /// to the end of the file.
    directory: &'a [u8],

    /// Entry point as a file offset. The value is calculated lazily the
    /// first time [`PE::entry_point_offset`] is called.
    entry_point: OnceCell<Option<u32>>,

    /// PE sections.
    sections: Vec<Section<'a>>,

    /// PE version information extracted from resources.
    version_info: OnceCell<Option<Vec<(String, String)>>>,

    /// PE resources. Resources are parsed lazily when [`PE::get_resources`]
    /// is called for the first time.
    resources: OnceCell<Option<Vec<Resource<'a>>>>,

    /// PE directory entries. Directory entries are parsed lazily when
    /// [`PE::get_dir_entries`] is called for the first time.
    dir_entries: OnceCell<Option<Vec<DirEntry>>>,

    /// Path to PDB file containing debug information for the PE.
    pdb_path: OnceCell<Option<&'a str>>,

    /// Map that with the DLLs imported by this PE file. Keys are DLL names,
    /// and values are vectors of [`ImportedFunc`] that contain information
    /// about each function imported from the DLL. We use an [`IndexMap`]
    /// instead of a [`HashMap`] because we want to maintain the order in
    /// which the DLLs appear in the import table, which is important while
    /// computing the imphash.
    imported_dlls: OnceCell<Option<IndexMap<&'a str, Vec<ImportedFunc<'a>>>>>,

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
        let (_, dos_hdr) = Self::parse_dos_header(input)?;

        // The PE header starts at the offset indicated by `dos_hdr.e_lfanew`.
        // Everything between offset 0 and `dos_hdr.e_lfanew` is stored in the
        // `dos_stub` slice, including the DOS header, the MS-DOS stub and the
        // rich signature.
        let (pe, dos_stub) = take(dos_hdr.e_lfanew)(input)?;

        // Parse the PE header (IMAGE_FILE_HEADER)
        let (optional_hdr, pe_hdr) = Self::parse_pe_header(pe)?;

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
                // The section parser needs the string table for resolving
                // some section names.
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
            dos_hdr,
            pe_hdr,
            optional_hdr,
            dos_stub,
            directory,
            ..Default::default()
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

                // According to the PE specification, file_alignment should
                // be a power of 2 between 512 and 64KB, inclusive. And the
                // default value is 512 (0x200). But PE files with lower values
                // (like 64, 32, and even 1) do exist in the wild and are
                // correctly handled by the Windows loader. For files with
                // very small values of file_alignment see:
                // http://www.phreedom.org/research/tinype/
                //
                // Also, according to Ero Carreras's pefile.py, file alignments
                // greater than 512, are actually ignored and 512 is used
                // instead.
                let file_alignment =
                    min(self.optional_hdr.file_alignment, 0x200);

                // Round down section_offset to a multiple of file_alignment.
                if let Some(rem) = section_offset.checked_rem(file_alignment) {
                    section_offset -= rem;
                }

                if self.optional_hdr.section_alignment >= 0x1000 {
                    // Round section_offset down to sector size (512 bytes).
                    section_offset =
                        section_offset.saturating_sub(section_offset % 0x200);
                }
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

    /// Returns the PE entry point as a file offset.
    pub fn entry_point_offset(&self) -> Option<u32> {
        *self
            .entry_point
            .get_or_init(|| self.rva_to_offset(self.optional_hdr.entry_point))
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
    pub fn get_rich_header(&self) -> Option<&RichHeader> {
        self.rich_header
            .get_or_init(|| {
                Self::parse_rich_header()(self.dos_stub)
                    .map(|(_, rich_header)| rich_header)
                    .ok()
            })
            .as_ref()
    }

    /// Returns PE version information.
    ///
    /// The information is returned as an iterator of (key,value) pairs,
    /// where keys are strings like "CompanyName", "FileDescription",
    /// "OriginalFilename", etc.
    pub fn get_version_info(&self) -> impl Iterator<Item = (&str, &str)> {
        self.version_info
            .get_or_init(|| self.parse_version_info())
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns the path to the PDB file that contains debug information
    /// for the PE file. The result is `None` either if the PE doesn't
    /// contain debug information, the debug information is not contained
    /// in a PDB file, or the file is corrupted and this information
    /// could not be parsed.
    ///
    /// For certain EFI binaries the result is not actually a path, but
    /// a CLSID. Is not clear what the CLSID means. Example:
    /// 6c2abf4b80a87e63eee2996e5cea8f004d49ec0c1806080fa72e960529cba14c
    pub fn get_pdb_path(&self) -> Option<&'a str> {
        *self.pdb_path.get_or_init(|| self.parse_dbg())
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
    /// The number of entries is limited to MAX_DIR_ENTRIES (16), which is the
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
            .and_then(|entry| Self::parse_dir_entry(entry).ok())
            .map(|(_reminder, entry)| entry)?;

        let start = self.rva_to_offset(dir_entry.addr)? as usize;
        let end = min(
            self.data.len(),
            start.saturating_add(dir_entry.size as usize),
        );

        self.data.get(start..end)
    }

    pub fn get_imports(
        &self,
    ) -> Option<impl Iterator<Item = (&'a str, &[ImportedFunc<'a>])>> {
        let imported_dlls = self
            .imported_dlls
            .get_or_init(|| self.parse_imports())
            .as_ref()?;

        Some(
            imported_dlls
                .iter()
                .map(|(name, funcs)| (*name, funcs.as_slice())),
        )
    }
}

impl<'a> PE<'a> {
    const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
    const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

    const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
    const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;

    const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

    const RICH_TAG: &'static [u8] = &[0x52_u8, 0x69, 0x63, 0x68];
    const DANS_TAG: &'static [u8] = &[0x44_u8, 0x61, 0x6e, 0x53];

    const SIZE_OF_PE_SIGNATURE: usize = 4; // size of PE signature (PE\0\0).
    const SIZE_OF_FILE_HEADER: usize = 20; // size of IMAGE_FILE_HEADER
    const SIZE_OF_DIR_ENTRY: usize = 8;
    const SIZE_OF_SYMBOL: u32 = 18;

    const MAX_PE_SECTIONS: usize = 96;
    const MAX_PE_IMPORTS: usize = 16384;
    const MAX_DIR_ENTRIES: usize = 16;

    fn parse_dos_header(input: &[u8]) -> IResult<&[u8], DOSHeader> {
        map(
            tuple((
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
            )),
            |(
                e_magic,    // DOS magic.
                e_cblp,     // Bytes on last page of file
                e_cp,       // Pages in file
                e_crlc,     // Relocations
                e_cparhdr,  // Size of header in paragraphs
                e_minalloc, // Minimum extra paragraphs needed
                e_maxalloc, // Maximum extra paragraphs needed
                e_ss,       // Initial (relative) SS value
                e_sp,       // Initial SP value
                e_csum,     // Checksum
                e_ip,       // Initial IP value
                e_cs,       // Initial (relative) CS value
                e_lfarlc,   // File address of relocation table
                e_ovno,     // Overlay number
                _,          // Reserved
                e_oemid,    // OEM identifier (for e_oeminfo)
                e_oeminfo,  // OEM information; e_oemid specific
                _,          // Reserved
                e_lfanew,   // File address of new exe header
            )| DOSHeader {
                e_magic,
                e_cblp,
                e_cp,
                e_crlc,
                e_cparhdr,
                e_minalloc,
                e_maxalloc,
                e_ss,
                e_sp,
                e_csum,
                e_ip,
                e_cs,
                e_lfarlc,
                e_ovno,
                e_oemid,
                e_oeminfo,
                e_lfanew,
            },
        )(input)
    }

    fn parse_pe_header(input: &[u8]) -> IResult<&[u8], PEHeader> {
        map(
            tuple((
                // Magic must be 'PE\0\0'
                verify(le_u32, |magic| *magic == 0x00004550),
                le_u16, // machine
                le_u16, // number_of_sections
                le_u32, // timestamp
                le_u32, // ptr_sym_table
                le_u32, // number_of_symbols
                le_u16, // size_of_optional_header
                le_u16, // characteristics
            )),
            |(
                _, // magic
                machine,
                number_of_sections,
                timestamp,
                symbol_table_offset,
                number_of_symbols,
                size_of_optional_header,
                characteristics,
            )| PEHeader {
                machine,
                number_of_sections,
                timestamp,
                symbol_table_offset,
                number_of_symbols,
                size_of_optional_header,
                characteristics,
            },
        )(input)
    }

    fn parse_opt_header() -> impl FnMut(&[u8]) -> IResult<&[u8], OptionalHeader>
    {
        move |input: &[u8]| {
            let mut opt_hdr = OptionalHeader::default();
            let base_of_data: Option<u32>;
            let image_base32: Option<u32>;
            let image_base64: Option<u64>;
            let mut remainder;

            (
                remainder,
                (
                    opt_hdr.magic,
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
                cond(
                    opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC,
                    le_u32,
                ),
                cond(
                    opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC,
                    le_u32,
                ),
                cond(
                    opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC,
                    le_u64,
                ),
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
                uint(opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
                uint(opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
                uint(opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
                uint(opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
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

    fn parse_dir_entry(input: &[u8]) -> IResult<&[u8], DirEntry> {
        map(tuple((le_u32, le_u32)), |(addr, size)| DirEntry { addr, size })(
            input,
        )
    }

    fn parse_rsrc_dir(input: &[u8]) -> IResult<&[u8], usize> {
        map(
            tuple((
                // characteristics must be 0
                verify(le_u32, |characteristics| *characteristics == 0),
                le_u32, // timestamp
                le_u16, // major_version
                le_u16, // minor_version
                le_u16, // number_of_named_entries
                le_u16, // number_of_id_entries
            )),
            |(
                _characteristics,
                _timestamp,
                _major_version,
                _minor_version,
                number_of_named_entries,
                number_of_id_entries,
            )| {
                number_of_id_entries as usize
                    + number_of_named_entries as usize
            },
        )(input)
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
                            //  length from characters to bytes
                            |len| len.saturating_mul(2),
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

    fn parse_rsrc_entry(input: &[u8]) -> IResult<&[u8], ResourceEntry> {
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

    /// Parses the VERSIONINFO structure stored in the version-information
    /// resource.
    ///
    /// This is tree-like structure where each node has a key, an optional
    /// value, and possible a certain number of children. Here is an example of
    /// how this structure typically looks like:
    ///
    /// ```text
    ///   key: "VS_VERSION_INFO"  value: VS_FIXEDFILEINFO struct
    ///   ├─ key: "StringFileInfo" value: empty
    ///   │  ├─ key: 090b0
    ///   │  │  ├─ key: "CompanyName" value: "Microsoft Corporation"
    ///   │  │  ├─ key: "FileDescription" value: "COM+"
    ///   │  │  ├─ key: "FileVersion" value: "2001.12.10941.16384"
    ///   │  │  ├─ key: "InternalName" value: "MTXEX.DLL"
    ///   │  │  ├─ key: "LegalCopyright" value: "© Microsoft Corporation"
    ///   │  │  ├─ key: "OriginalFilename" value: "MTXEX.DLL"
    ///   │  │  ├─ key: "ProductName" value: "Microsoft® Windows® Operating System"
    ///   │  │  └─ key: "ProductVersion" value: "10.0.17763.1"
    ///   │  └─ ...
    ///   ├─ key: "StringFileInfo" value: empty
    ///   │  └─ ...
    ///   └─ key: "VarFileInfo" value: empty
    ///      └─ key: "Translation" value: [09 04 B0 04
    /// ```
    ///
    /// See: https://learn.microsoft.com/en-us/windows/win32/menurc/version-information
    ///
    /// This parser returns a vector of (key, value) pairs, both of [`String`]
    /// type, with the leaf nodes that descend from "StringFileInfo" nodes. In
    /// the example above the results would be:
    ///
    /// ```text
    /// [
    ///     ("CompanyName", "Microsoft Corporation"),
    ///     ("FileDescription", "COM+"),
    ///     ("FileVersion", "2001.12.10941.16384 (WinBuild.160101.0800)"),
    ///     ("InternalName", "MTXEX.DLL"),
    ///     ("LegalCopyright", "© Microsoft Corporation. All rights reserved."),
    ///     ("OriginalFilename", "MTXEX.DLL"),
    ///     ("ProductName", "Microsoft® Windows® Operating System"),
    ///     ("ProductVersion", "10.0.17763.1"),
    /// ]
    /// ```
    fn parse_version_info(&self) -> Option<Vec<(String, String)>> {
        // Find the resource with ID = RESOURCE_TYPE_VERSION
        let version_info_rsrc = self.get_resources().iter().find(|r| {
            r.type_id
                == ResourceId::Id(
                    pe::ResourceType::RESOURCE_TYPE_VERSION as u32,
                )
        })?;

        let version_info_raw =
            self.data.get(version_info_rsrc.offset? as usize..)?;

        let (_, (_key, _fixed_file_info, (_, strings))) =
            Self::parse_info_with_key(
                "VS_VERSION_INFO",
                version_info_raw,
                tuple((
                    le_u32, // signature
                    le_u32, // struct_version
                    le_u32, // file_version_high
                    le_u32, // file_version_low
                    le_u32, // dwProductVersionMS;
                    le_u32, // dwProductVersionLS;
                    le_u32, // DWORD dwFileFlagsMask;
                    le_u32, // DWORD dwFileFlags;
                    le_u32, // DWORD dwFileOS;
                    le_u32, // DWORD dwFileType;
                    le_u32, // DWORD dwFileSubtype;
                    le_u32, // DWORD dwFileDateMS;
                    le_u32, // DWORD dwFileDateLS;
                )),
                // Possible children are StringFileInfo and VarFileInfo
                // structures. Both are optional and they can appear in any
                // order. Usually StringFileInfo appears first, but
                // 09e7d832320e51bcc80b9aecde2a4135267a9b0156642a9596a62e85c9998cc9
                // is an example where VarFileInfo appears first.
                permutation((
                    opt(Self::parse_var_file_info),
                    opt(Self::parse_string_file_info),
                )),
            )
            .ok()?;

        strings
    }

    /// https://learn.microsoft.com/en-us/windows/win32/menurc/stringfileinfo
    fn parse_string_file_info(
        input: &[u8],
    ) -> IResult<&[u8], Vec<(String, String)>> {
        map(
            move |input| {
                Self::parse_info_with_key(
                    "StringFileInfo",
                    input,
                    // StringFileInfo doesn't have any value, so the value's parser
                    // is simply `fail`, so that it fails if called.
                    fail::<&[u8], (), Error>,
                    // The children are one or more StringTable structures.
                    fold_many1(
                        Self::parse_file_version_string_table,
                        Vec::new,
                        |mut all_strings: Vec<_>, strings| {
                            all_strings.extend(strings);
                            all_strings
                        },
                    ),
                )
            },
            |(_, _, strings)| strings,
        )(input)
    }

    /// https://learn.microsoft.com/en-us/windows/win32/menurc/varfileinfo
    fn parse_var_file_info(input: &[u8]) -> IResult<&[u8], ()> {
        map(
            move |input| {
                Self::parse_info_with_key(
                    "VarFileInfo",
                    input,
                    // VarFileInfo doesn't have any value, so the value's parser
                    // is simply `fail`, so that it fails if called.
                    fail::<&[u8], (), Error>,
                    // We are not really interested in parsing the children of
                    // VarFileInfo, just ignore them and succeed.
                    success(()),
                )
            },
            |(_, _, strings)| strings,
        )(input)
    }

    /// https://learn.microsoft.com/en-us/windows/win32/menurc/stringtable
    fn parse_file_version_string_table(
        input: &[u8],
    ) -> IResult<&[u8], Vec<(String, String)>> {
        map(
            Self::parse_info(
                // StringTable doesn't have any value, so the value's parser
                // is simply `fail`, so that it fails if called.
                fail::<&[u8], (), Error>,
                // The children are one or more String structures.
                many1(Self::parse_file_version_string),
            ),
            |(_, _, strings)| strings,
        )(input)
    }

    /// Parser that returns a string within the file version information
    /// structure.
    ///
    /// Returns (key, value) pairs where keys are strings like "CompanyName",
    /// "FileDescription", "LegalCopyright", etc; and values are their
    /// associates string values.
    ///
    /// All strings are returned as a byte slice containing a UTF-16 LE string.
    ///
    /// https://learn.microsoft.com/en-us/windows/win32/menurc/string-str
    fn parse_file_version_string(
        input: &[u8],
    ) -> IResult<&[u8], (String, String)> {
        map(
            Self::parse_info(
                // The value is a null-terminated UTF-16LE string.
                utf16_le_string(),
                // String doesn't have any children, so the value's parser
                // is simply `fail`, so that it fails if called.
                success(()),
            ),
            |(key, value, _)| (key, value.unwrap_or_default()),
        )(input)
    }

    /// Like [`PE::parse_info`], but checks that the structure's key matches
    /// `expected_key` and fails if not.
    fn parse_info_with_key<'b, F, G, V, C>(
        expected_key: &'static str,
        input: &'b [u8],
        value_parser: F,
        children_parser: G,
    ) -> IResult<&'b [u8], (String, Option<V>, C)>
    where
        F: Parser<&'b [u8], V, Error<'b>>,
        G: Parser<&'b [u8], C, Error<'b>>,
    {
        verify(
            Self::parse_info(value_parser, children_parser),
            |(key, _, _)| key == expected_key,
        )(input)
    }

    /// Generic parser that parses one of the nodes that conform the
    /// file version information tree.
    ///
    /// The tree is conformed of nested, variable-length structures with the
    /// following layout:
    ///
    /// ```text
    /// length    - length of the whole structure, including the length itself
    ///             and its children.
    /// value_len - length of the value stored in this structure, if any.
    /// type      - type of value (0: binary, 1: text)
    /// key       - null-terminated UTF-16LE string that identifies the node
    ///             in the tree.
    /// padding1  - 0 or more bytes that align the next field to a 32-bits
    ///             boundary
    /// value     - arbitrary bytes, its size is indicated in value_len. If
    ///             type is 1 (text) value_len is the number of UTF-16LE
    ///             characters, not bytes.
    /// padding1  - 0 or more bytes that align the next field to a 32-bits
    ///             boundary
    /// children  - data that corresponds to the children of this structure
    /// ```
    ///
    /// This function returns a parser for one of these structures, where the
    /// parser for the value and the children are passed as arguments.
    fn parse_info<'b, F, G, V, C>(
        mut value_parser: F,
        mut children_parser: G,
    ) -> impl FnMut(&'b [u8]) -> IResult<&'b [u8], (String, Option<V>, C)>
    where
        F: Parser<&'b [u8], V, Error<'b>>,
        G: Parser<&'b [u8], C, Error<'b>>,
    {
        move |input: &'b [u8]| {
            // Read the structure's length and round it up to a 32-bits
            // boundary.
            let (_, length) = le_u16(input)?;
            let length = Self::round_up(length);

            // Read the structure's bytes.
            let (remainder, structure) = take(length)(input)?;

            // Parse the structure's first fields.
            let (_, (consumed, (_, mut value_len, type_, key))) =
                consumed(tuple((
                    le_u16,            // length
                    le_u16,            // value_length
                    le_u16,            // type
                    utf16_le_string(), // key
                )))(structure)?;

            // The structure may contain padding bytes after the key for
            // aligning the rest of the structure to a 32-bits boundary.
            // Here we get the length of the data consumed so far and round
            // it up to a 32-bits boundary.
            let alignment = Self::round_up(consumed.len());

            // Then take `alignment` bytes from the start of the structure.
            let (data, _) = take(alignment)(structure)?;

            // If type is 1 the value is of text type and it's length is in
            // characters. As characters are UTF-16, multiply by two to get
            // the size in bytes.
            if type_ == 1 {
                value_len = value_len.saturating_mul(2);
            }

            let value_len = Self::round_up(value_len);

            // Parse the value, if value_len is greater than zero.
            let (data, value) = cond(
                value_len > 0,
                take(value_len).and_then(|v| value_parser.parse(v)),
            )(data)?;

            let (_, children) = children_parser.parse(data)?;

            Ok((remainder, (key, value, children)))
        }
    }

    /// Round up an offset to the next 32-bit boundary.
    fn round_up<O: ToUsize>(offset: O) -> usize {
        // TODO: use usize:div_ceil when we bump the MSRV to 1.73.0.
        num::Integer::div_ceil(&offset.to_usize(), &4) * 4
    }

    /// Given a RVA, return a byte slice with the content of the PE that
    /// goes from that RVA to the end of the file.
    #[inline]
    fn data_at_rva(&self, rva: u32) -> Option<&'a [u8]> {
        let offset = self.rva_to_offset(rva)?;
        self.data.get(offset as usize..)
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
                match Self::parse_rsrc_dir(rsrc_dir) {
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
                        Self::parse_rsrc_entry(entry_data)
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
        count(Self::parse_dir_entry, num_dir_entries)(self.directory)
            .map(|(_, entries)| entries)
            .ok()
    }

    fn parse_dbg(&self) -> Option<&'a str> {
        let dbg_section =
            self.get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_DEBUG)?;

        let entries = many0(Self::parse_dbg_dir_entry)(dbg_section)
            .map(|(_, entries)| entries)
            .ok()?;

        for entry in entries
            .iter()
            .filter(|entry| entry.type_ == Self::IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            // The debug info offset may be present either as RVA or as raw
            // offset. The RVA has higher priority, but if it is 0 or can't
            // be resolved to a file offset, then the raw offset is used
            // instead.
            let offset = if entry.virtual_address != 0 {
                self.rva_to_offset(entry.virtual_address)
            } else {
                None
            };

            let offset = match offset.or(Some(entry.raw_data_offset)) {
                Some(offset) if offset > 0 => offset,
                Some(_) | None => continue,
            };

            let cv_info = match self.data.get(offset as usize..) {
                Some(cv_info) => cv_info,
                None => continue,
            };

            // The CodeView information can come in different formats, but all
            // of them start with 32-bits signature that allows to distinguish
            // between them. Here we recognize three different signatures:
            // "RSDS" (PDB 7.0), "NB10" (PDB 2.0) and "MTOC".
            //
            // Signatures "NDB09" (CodeView 4.10) and "NDB11" (CodeView 5.0)
            // also exists, but those are used when debug information is
            // included in the PE itself, instead of an external PDB file,
            // therefore in such cases there's no PDB file name to extract.
            //
            // See: https://www.debuginfo.com/articles/debuginfomatch.html
            match alt((
                // "RSDS" means that the debug information is stored in a
                // PDB 7.0 file. The structure is:
                //
                //   DWORD      signature;
                //   BYTE[16]   guid;
                //   DWORD      age;
                //   BYTE[..]   pdb_path;
                //
                tuple((
                    verify(le_u32::<&[u8], Error>, |signature| {
                        *signature == 0x53445352 // "RSDS"
                    }),
                    take(20_usize), // skip guid and age
                    take_till(|c| c == 0),
                )),
                // "NB10" means that the debug information is stored in a
                // PDB 2.0 file. The structure is:
                //
                //   DWORD      signature;
                //   DWORD      offset;
                //   DWORD      timestamp;
                //   DWORD      age;
                //   BYTE[..]   pdb_path;
                //
                tuple((
                    verify(le_u32::<&[u8], Error>, |signature| {
                        *signature == 0x3031424e // "NB10"
                    }),
                    take(12_usize), // skip offset, timestamp, and age
                    take_till(|c| c == 0),
                )),
                //
                //   DWORD      signature;
                //   BYTE[16]   guid;
                //   BYTE[..]   pdb_path;
                //
                tuple((
                    verify(le_u32::<&[u8], Error>, |signature| {
                        *signature == 0x434f544d // "MTOC"
                    }),
                    take(16_usize), // skip guid
                    take_till(|c| c == 0),
                )),
            ))(cv_info)
            {
                Ok((_, (_signature, _padding, pdb_path))) => {
                    return from_utf8(pdb_path).ok()
                }
                Err(_) => continue,
            };
        }

        None
    }

    /// Parse the IMAGE_DEBUG_DIRECTORY structure.
    /// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_debug_directory
    fn parse_dbg_dir_entry(input: &[u8]) -> IResult<&[u8], DbgDirEntry> {
        map(
            tuple((
                le_u32, // characteristics
                le_u32, // timestamp
                le_u16, // major_version
                le_u16, // minor_version
                le_u32, // type
                le_u32, // raw_data_size
                le_u32, // virtual_address
                le_u32, // raw_data_offset
            )),
            |(
                characteristics,
                timestamp,
                major_version,
                minor_version,
                type_,
                raw_data_size,
                virtual_address,
                raw_data_offset,
            )| {
                DbgDirEntry {
                    characteristics,
                    timestamp,
                    major_version,
                    minor_version,
                    type_,
                    raw_data_size,
                    virtual_address,
                    raw_data_offset,
                }
            },
        )(input)
    }

    fn parse_imports(
        &self,
    ) -> Option<IndexMap<&'a str, Vec<ImportedFunc<'a>>>> {
        let imports_section =
            self.get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_IMPORT)?;

        // Parse import descriptors until finding one that is empty (filled
        // with null values), which indicates the end of the directory table;
        // or until `MAX_PE_IMPORTS` is reached.
        let import_descriptors = many_m_n(
            0,
            Self::MAX_PE_IMPORTS,
            verify(Self::parse_import_descriptor, |d| {
                d.original_first_thunk != 0 || d.first_thunk != 0
            }),
        )(imports_section)
        .map(|(_, import_descriptors)| import_descriptors)
        .ok()?;

        let is_32_bits =
            self.optional_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC;

        let mut imported_funcs: IndexMap<&str, Vec<ImportedFunc>> =
            IndexMap::new();

        for descriptor in import_descriptors {
            let dll_name =
                if let Some(name) = self.dll_name_at_rva(descriptor.name) {
                    name
                } else {
                    continue;
                };

            let thunks = match if descriptor.original_first_thunk > 0 {
                self.data_at_rva(descriptor.original_first_thunk)
            } else {
                self.data_at_rva(descriptor.first_thunk)
            } {
                Some(thunk) => thunk,
                None => continue,
            };

            // Parse the thunks, which are an array of 64-bits or 32-bits
            // values, depending on whether this is 64-bits PE file. The
            // array is terminated by a null thunk.
            let mut thunks = iterator(
                thunks,
                verify(uint(is_32_bits), |thunk| *thunk != 0),
            );

            for (i, thunk) in &mut thunks.enumerate() {
                // If the most significant bit is set, this is an import by
                // ordinal. The most significant bit depends on whether this
                // is a 64-bits PE.
                let import_by_ordinal = if is_32_bits {
                    thunk & 0x80000000 != 0
                } else {
                    thunk & 0x8000000000000000 != 0
                };

                let mut func = ImportedFunc::default();

                if import_by_ordinal {
                    let ordinal = (thunk & 0xffff) as u16;
                    func.ordinal = Some(ordinal);
                    func.name = ord_to_name(dll_name, ordinal);
                    func.rva = descriptor.first_thunk.saturating_add(i as u32);
                } else if let Ok(offset) = TryInto::<u32>::try_into(thunk) {
                    if let Some(name) =
                        self.parse_at_rva(offset, Self::parse_import_by_name)
                    {
                        func.name = from_utf8(name).ok();
                        func.rva = descriptor.first_thunk.saturating_add(
                            (i * if is_32_bits { 4 } else { 8 }) as u32,
                        );
                    }
                }

                if func.ordinal.is_some() || func.name.is_some() {
                    imported_funcs.entry(dll_name).or_default().push(func)
                }
            }
        }

        Some(imported_funcs)
    }

    fn parse_import_descriptor(
        input: &[u8],
    ) -> IResult<&[u8], ImportDescriptor> {
        map(
            tuple((
                le_u32, // original_first_thunk
                le_u32, // timestamp
                le_u32, // forwarder_chain
                le_u32, // name
                le_u32, // first_thunk
            )),
            |(
                original_first_thunk,
                timestamp,
                forwarder_chain,
                name,
                first_thunk,
            )| {
                ImportDescriptor {
                    original_first_thunk,
                    timestamp,
                    forwarder_chain,
                    name,
                    first_thunk,
                }
            },
        )(input)
    }

    fn parse_import_by_name(input: &[u8]) -> IResult<&[u8], &[u8]> {
        map(
            tuple((
                le_u16,                       // hint
                take_till(|c: u8| c == 0_u8), // name
            )),
            |(_, name)| name,
        )(input)
    }

    fn parse_at_rva<T, P>(&self, rva: u32, mut parser: P) -> Option<T>
    where
        P: FnMut(&'a [u8]) -> IResult<&'a [u8], T>,
    {
        let data = self.data_at_rva(rva)?;
        parser(data).map(|(_, result)| result).ok()
    }

    fn dll_name_at_rva(&self, rva: u32) -> Option<&'a str> {
        let dll_name = self.parse_at_rva(rva, take_till(|c| c == 0))?;
        let dll_name = from_utf8(dll_name).ok()?;

        for c in dll_name.chars() {
            if matches!(c, ' ' | '"' | '*' | '<' | '>' | '?' | '|') {
                return None;
            }
        }

        Some(dll_name)
    }
}

#[rustfmt::skip]
impl From<PE<'_>> for pe::PE {
    fn from(pe: PE) -> Self {
        let mut result = pe::PE::new();
        
        result.set_is_pe(true);
        result.machine = pe
            .pe_hdr
            .machine
            .try_into()
            .ok()
            .map(EnumOrUnknown::<pe::Machine>::from_i32);

        result.set_timestamp(pe.pe_hdr.timestamp);
        result.set_characteristics(pe.pe_hdr.characteristics.into());
        result.set_number_of_sections(pe.pe_hdr.number_of_sections.into());
        result.set_pointer_to_symbol_table(pe.pe_hdr.symbol_table_offset);
        result.set_number_of_symbols(pe.pe_hdr.number_of_symbols);
        result.set_size_of_optional_header(pe.pe_hdr.size_of_optional_header.into());

        result.subsystem = pe
            .optional_hdr
            .subsystem
            .try_into()
            .ok()
            .map(EnumOrUnknown::<pe::Subsystem>::from_i32);
        
        result.set_size_of_code(pe.optional_hdr.size_of_code);
        result.set_base_of_code(pe.optional_hdr.base_of_code);
        result.base_of_data = pe.optional_hdr.base_of_data;
        result.set_entry_point_raw(pe.optional_hdr.entry_point);
        result.entry_point = pe.entry_point_offset();
        result.set_section_alignment(pe.optional_hdr.section_alignment);
        result.set_file_alignment(pe.optional_hdr.file_alignment);
        result.set_loader_flags(pe.optional_hdr.loader_flags);
        result.set_dll_characteristics(pe.optional_hdr.dll_characteristics.into());
        result.set_checksum(pe.optional_hdr.checksum);
        result.set_win32_version_value(pe.optional_hdr.win32_version);
        result.set_size_of_stack_reserve(pe.optional_hdr.size_of_stack_reserve);
        result.set_size_of_stack_commit(pe.optional_hdr.size_of_stack_commit);
        result.set_size_of_heap_reserve(pe.optional_hdr.size_of_heap_reserve);
        result.set_size_of_heap_commit(pe.optional_hdr.size_of_heap_commit);
        result.pdb_path = pe.get_pdb_path().map(String::from);
        result.set_number_of_rva_and_sizes(pe.optional_hdr.number_of_rva_and_sizes);
        result.image_base = pe.optional_hdr.image_base;
        result.set_size_of_image(pe.optional_hdr.size_of_image);
        result.set_size_of_headers(pe.optional_hdr.size_of_headers);
        result.set_size_of_initialized_data(pe.optional_hdr.size_of_initialized_data);
        result.set_size_of_uninitialized_data(pe.optional_hdr.size_of_uninitialized_data);

        // TODO
        // number_of_version_infos
        // opthdr_magic
        
        result.linker_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_linker_version.into()),
            minor: Some(pe.optional_hdr.minor_linker_version.into()),
            ..Default::default()
        });

        result.os_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_os_version.into()),
            minor: Some(pe.optional_hdr.minor_os_version.into()),
            ..Default::default()
        });

        result.image_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_image_version.into()),
            minor: Some(pe.optional_hdr.minor_image_version.into()),
            ..Default::default()
        });

        result.subsystem_version = MessageField::some(pe::Version {
            major: Some(pe.optional_hdr.major_subsystem_version.into()),
            minor: Some(pe.optional_hdr.minor_subsystem_version.into()),
            ..Default::default()
        });
        
        result
            .data_directories
            .extend(pe.get_dir_entries().iter().map(pe::DirEntry::from));

        result
            .sections
            .extend(pe.get_sections().iter().map(pe::Section::from));

        result
            .resources
            .extend(pe.get_resources().iter().map(pe::Resource::from));

        for (key, value) in pe.get_version_info() {
            let mut kv = pe::KeyValue::new();
            kv.key = Some(key.to_owned());
            kv.value = Some(value.to_owned());
            result.version_info_list.push(kv);
            // TODO: populate the `version_info` map when we find a way for
            // maintaining an stable order when dumping map fields in text
            // form. The issue we have now is that the order changes every
            // time the test cases are run, and the output produced don't
            // match the golden files.
            // result.version_info.insert(key.to_owned(), value.to_owned());
        }
        
        let mut num_imported_funcs = 0;
        
        if let Some(imports) = pe.get_imports() {
            for (dll_name, functions) in imports {
                let mut import = pe::Import::new();
                import.library_name = Some(dll_name.to_owned());
                import.functions = functions.iter().map(pe::Function::from).collect();
                num_imported_funcs += import.functions.len();
                result.import_details.push(import);
            }
        }
        
        result.set_number_of_imported_functions(num_imported_funcs as u64);
        
        if let Some(rich_header) = pe.get_rich_header() {
            result.rich_signature = MessageField::some(pe::RichSignature {
                offset: Some(rich_header.offset.try_into().unwrap()),
                length: Some(rich_header.raw_data.len().try_into().unwrap()),
                key: Some(rich_header.key),
                // TODO: implement some mechanism for returning slices
                // backed by the scanned data without copy.
                raw_data: Some(rich_header.raw_data.to_vec()),
                clear_data: Some(rich_header.clear_data.clone()),
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
                ..Default::default()
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
                    ..Default::default()
                },
                _ => pe::Overlay {
                    offset: Some(0),
                    size: Some(0),
                    ..Default::default()
                },
            });

        result
    }
}

#[allow(dead_code)]
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
    magic: u16,
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

#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(Debug)]
pub struct ImportDescriptor {
    original_first_thunk: u32,
    timestamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[derive(Debug, Default)]
pub struct ImportedFunc<'a> {
    name: Option<&'a str>,
    ordinal: Option<u16>,
    rva: u32,
}

impl From<&ImportedFunc<'_>> for pe::Function {
    fn from(value: &ImportedFunc) -> Self {
        let mut func = pe::Function::new();
        func.rva = Some(value.rva);
        func.ordinal = value.ordinal.map(|ordinal| ordinal.into());
        func.name = value.name.map(|name| name.to_owned());
        func
    }
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

#[derive(Debug)]
pub struct DbgDirEntry {
    /// Reserved.
    characteristics: u32,
    /// The time and date the debugging information was created.
    timestamp: u32,
    /// The major version number of the debugging information format.
    major_version: u16,
    /// The minor version number of the debugging information format.
    minor_version: u16,
    /// The format of the debugging information.
    type_: u32,
    /// The size of the debugging information, in bytes. This value does not
    /// include the debug directory itself.
    raw_data_size: u32,
    /// The address of the debugging information when the image is loaded,
    /// relative to the image base.
    virtual_address: u32,
    /// Offset within the file where debugging information is found.
    raw_data_offset: u32,
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

/// Parser that reads a null-terminated UTF-16LE string.
///
/// The result is a UTF-8 string,
fn utf16_le_string() -> impl FnMut(&[u8]) -> IResult<&[u8], String> {
    move |input: &[u8]| {
        // Read UTF-16 chars until a null terminator is found.
        let (remainder, string) =
            many0(verify(le_u16, |c| *c != 0_u16))(input)?;

        // Consume the null-terminator.
        let (remainder, _) = take(2_usize)(remainder)?;

        let s = String::from_utf16_lossy(string.as_slice());

        Ok((remainder, s))
    }
}

/// Convert ordinal number to function name for some well-known DLLs.
fn ord_to_name(dll_name: &str, ordinal: u16) -> Option<&'static str> {
    match dll_name.to_ascii_lowercase().as_str() {
        "ws2_32.dll" | "wsock32.dll" => wsock32_ord_to_name(ordinal),
        "oleaut32.dll" => oleaut32_ord_to_name(ordinal),
        _ => None,
    }
}

/// Convert ordinal number to function name for oleaut32.dll.
fn oleaut32_ord_to_name(ordinal: u16) -> Option<&'static str> {
    match ordinal {
        2 => Some("SysAllocString"),
        3 => Some("SysReAllocString"),
        4 => Some("SysAllocStringLen"),
        5 => Some("SysReAllocStringLen"),
        6 => Some("SysFreeString"),
        7 => Some("SysStringLen"),
        8 => Some("VariantInit"),
        9 => Some("VariantClear"),
        10 => Some("VariantCopy"),
        11 => Some("VariantCopyInd"),
        12 => Some("VariantChangeType"),
        13 => Some("VariantTimeToDosDateTime"),
        14 => Some("DosDateTimeToVariantTime"),
        15 => Some("SafeArrayCreate"),
        16 => Some("SafeArrayDestroy"),
        17 => Some("SafeArrayGetDim"),
        18 => Some("SafeArrayGetElemsize"),
        19 => Some("SafeArrayGetUBound"),
        20 => Some("SafeArrayGetLBound"),
        21 => Some("SafeArrayLock"),
        22 => Some("SafeArrayUnlock"),
        23 => Some("SafeArrayAccessData"),
        24 => Some("SafeArrayUnaccessData"),
        25 => Some("SafeArrayGetElement"),
        26 => Some("SafeArrayPutElement"),
        27 => Some("SafeArrayCopy"),
        28 => Some("DispGetParam"),
        29 => Some("DispGetIDsOfNames"),
        30 => Some("DispInvoke"),
        31 => Some("CreateDispTypeInfo"),
        32 => Some("CreateStdDispatch"),
        33 => Some("RegisterActiveObject"),
        34 => Some("RevokeActiveObject"),
        35 => Some("GetActiveObject"),
        36 => Some("SafeArrayAllocDescriptor"),
        37 => Some("SafeArrayAllocData"),
        38 => Some("SafeArrayDestroyDescriptor"),
        39 => Some("SafeArrayDestroyData"),
        40 => Some("SafeArrayRedim"),
        41 => Some("SafeArrayAllocDescriptorEx"),
        42 => Some("SafeArrayCreateEx"),
        43 => Some("SafeArrayCreateVectorEx"),
        44 => Some("SafeArraySetRecordInfo"),
        45 => Some("SafeArrayGetRecordInfo"),
        46 => Some("VarParseNumFromStr"),
        47 => Some("VarNumFromParseNum"),
        48 => Some("VarI2FromUI1"),
        49 => Some("VarI2FromI4"),
        50 => Some("VarI2FromR4"),
        51 => Some("VarI2FromR8"),
        52 => Some("VarI2FromCy"),
        53 => Some("VarI2FromDate"),
        54 => Some("VarI2FromStr"),
        55 => Some("VarI2FromDisp"),
        56 => Some("VarI2FromBool"),
        57 => Some("SafeArraySetIID"),
        58 => Some("VarI4FromUI1"),
        59 => Some("VarI4FromI2"),
        60 => Some("VarI4FromR4"),
        61 => Some("VarI4FromR8"),
        62 => Some("VarI4FromCy"),
        63 => Some("VarI4FromDate"),
        64 => Some("VarI4FromStr"),
        65 => Some("VarI4FromDisp"),
        66 => Some("VarI4FromBool"),
        67 => Some("SafeArrayGetIID"),
        68 => Some("VarR4FromUI1"),
        69 => Some("VarR4FromI2"),
        70 => Some("VarR4FromI4"),
        71 => Some("VarR4FromR8"),
        72 => Some("VarR4FromCy"),
        73 => Some("VarR4FromDate"),
        74 => Some("VarR4FromStr"),
        75 => Some("VarR4FromDisp"),
        76 => Some("VarR4FromBool"),
        77 => Some("SafeArrayGetVartype"),
        78 => Some("VarR8FromUI1"),
        79 => Some("VarR8FromI2"),
        80 => Some("VarR8FromI4"),
        81 => Some("VarR8FromR4"),
        82 => Some("VarR8FromCy"),
        83 => Some("VarR8FromDate"),
        84 => Some("VarR8FromStr"),
        85 => Some("VarR8FromDisp"),
        86 => Some("VarR8FromBool"),
        87 => Some("VarFormat"),
        88 => Some("VarDateFromUI1"),
        89 => Some("VarDateFromI2"),
        90 => Some("VarDateFromI4"),
        91 => Some("VarDateFromR4"),
        92 => Some("VarDateFromR8"),
        93 => Some("VarDateFromCy"),
        94 => Some("VarDateFromStr"),
        95 => Some("VarDateFromDisp"),
        96 => Some("VarDateFromBool"),
        97 => Some("VarFormatDateTime"),
        98 => Some("VarCyFromUI1"),
        99 => Some("VarCyFromI2"),
        100 => Some("VarCyFromI4"),
        101 => Some("VarCyFromR4"),
        102 => Some("VarCyFromR8"),
        103 => Some("VarCyFromDate"),
        104 => Some("VarCyFromStr"),
        105 => Some("VarCyFromDisp"),
        106 => Some("VarCyFromBool"),
        107 => Some("VarFormatNumber"),
        108 => Some("VarBstrFromUI1"),
        109 => Some("VarBstrFromI2"),
        110 => Some("VarBstrFromI4"),
        111 => Some("VarBstrFromR4"),
        112 => Some("VarBstrFromR8"),
        113 => Some("VarBstrFromCy"),
        114 => Some("VarBstrFromDate"),
        115 => Some("VarBstrFromDisp"),
        116 => Some("VarBstrFromBool"),
        117 => Some("VarFormatPercent"),
        118 => Some("VarBoolFromUI1"),
        119 => Some("VarBoolFromI2"),
        120 => Some("VarBoolFromI4"),
        121 => Some("VarBoolFromR4"),
        122 => Some("VarBoolFromR8"),
        123 => Some("VarBoolFromDate"),
        124 => Some("VarBoolFromCy"),
        125 => Some("VarBoolFromStr"),
        126 => Some("VarBoolFromDisp"),
        127 => Some("VarFormatCurrency"),
        128 => Some("VarWeekdayName"),
        129 => Some("VarMonthName"),
        130 => Some("VarUI1FromI2"),
        131 => Some("VarUI1FromI4"),
        132 => Some("VarUI1FromR4"),
        133 => Some("VarUI1FromR8"),
        134 => Some("VarUI1FromCy"),
        135 => Some("VarUI1FromDate"),
        136 => Some("VarUI1FromStr"),
        137 => Some("VarUI1FromDisp"),
        138 => Some("VarUI1FromBool"),
        139 => Some("VarFormatFromTokens"),
        140 => Some("VarTokenizeFormatString"),
        141 => Some("VarAdd"),
        142 => Some("VarAnd"),
        143 => Some("VarDiv"),
        144 => Some("DllCanUnloadNow"),
        145 => Some("DllGetClassObject"),
        146 => Some("DispCallFunc"),
        147 => Some("VariantChangeTypeEx"),
        148 => Some("SafeArrayPtrOfIndex"),
        149 => Some("SysStringByteLen"),
        150 => Some("SysAllocStringByteLen"),
        151 => Some("DllRegisterServer"),
        152 => Some("VarEqv"),
        153 => Some("VarIdiv"),
        154 => Some("VarImp"),
        155 => Some("VarMod"),
        156 => Some("VarMul"),
        157 => Some("VarOr"),
        158 => Some("VarPow"),
        159 => Some("VarSub"),
        160 => Some("CreateTypeLib"),
        161 => Some("LoadTypeLib"),
        162 => Some("LoadRegTypeLib"),
        163 => Some("RegisterTypeLib"),
        164 => Some("QueryPathOfRegTypeLib"),
        165 => Some("LHashValOfNameSys"),
        166 => Some("LHashValOfNameSysA"),
        167 => Some("VarXor"),
        168 => Some("VarAbs"),
        169 => Some("VarFix"),
        170 => Some("OaBuildVersion"),
        171 => Some("ClearCustData"),
        172 => Some("VarInt"),
        173 => Some("VarNeg"),
        174 => Some("VarNot"),
        175 => Some("VarRound"),
        176 => Some("VarCmp"),
        177 => Some("VarDecAdd"),
        178 => Some("VarDecDiv"),
        179 => Some("VarDecMul"),
        180 => Some("CreateTypeLib2"),
        181 => Some("VarDecSub"),
        182 => Some("VarDecAbs"),
        183 => Some("LoadTypeLibEx"),
        184 => Some("SystemTimeToVariantTime"),
        185 => Some("VariantTimeToSystemTime"),
        186 => Some("UnRegisterTypeLib"),
        187 => Some("VarDecFix"),
        188 => Some("VarDecInt"),
        189 => Some("VarDecNeg"),
        190 => Some("VarDecFromUI1"),
        191 => Some("VarDecFromI2"),
        192 => Some("VarDecFromI4"),
        193 => Some("VarDecFromR4"),
        194 => Some("VarDecFromR8"),
        195 => Some("VarDecFromDate"),
        196 => Some("VarDecFromCy"),
        197 => Some("VarDecFromStr"),
        198 => Some("VarDecFromDisp"),
        199 => Some("VarDecFromBool"),
        200 => Some("GetErrorInfo"),
        201 => Some("SetErrorInfo"),
        202 => Some("CreateErrorInfo"),
        203 => Some("VarDecRound"),
        204 => Some("VarDecCmp"),
        205 => Some("VarI2FromI1"),
        206 => Some("VarI2FromUI2"),
        207 => Some("VarI2FromUI4"),
        208 => Some("VarI2FromDec"),
        209 => Some("VarI4FromI1"),
        210 => Some("VarI4FromUI2"),
        211 => Some("VarI4FromUI4"),
        212 => Some("VarI4FromDec"),
        213 => Some("VarR4FromI1"),
        214 => Some("VarR4FromUI2"),
        215 => Some("VarR4FromUI4"),
        216 => Some("VarR4FromDec"),
        217 => Some("VarR8FromI1"),
        218 => Some("VarR8FromUI2"),
        219 => Some("VarR8FromUI4"),
        220 => Some("VarR8FromDec"),
        221 => Some("VarDateFromI1"),
        222 => Some("VarDateFromUI2"),
        223 => Some("VarDateFromUI4"),
        224 => Some("VarDateFromDec"),
        225 => Some("VarCyFromI1"),
        226 => Some("VarCyFromUI2"),
        227 => Some("VarCyFromUI4"),
        228 => Some("VarCyFromDec"),
        229 => Some("VarBstrFromI1"),
        230 => Some("VarBstrFromUI2"),
        231 => Some("VarBstrFromUI4"),
        232 => Some("VarBstrFromDec"),
        233 => Some("VarBoolFromI1"),
        234 => Some("VarBoolFromUI2"),
        235 => Some("VarBoolFromUI4"),
        236 => Some("VarBoolFromDec"),
        237 => Some("VarUI1FromI1"),
        238 => Some("VarUI1FromUI2"),
        239 => Some("VarUI1FromUI4"),
        240 => Some("VarUI1FromDec"),
        241 => Some("VarDecFromI1"),
        242 => Some("VarDecFromUI2"),
        243 => Some("VarDecFromUI4"),
        244 => Some("VarI1FromUI1"),
        245 => Some("VarI1FromI2"),
        246 => Some("VarI1FromI4"),
        247 => Some("VarI1FromR4"),
        248 => Some("VarI1FromR8"),
        249 => Some("VarI1FromDate"),
        250 => Some("VarI1FromCy"),
        251 => Some("VarI1FromStr"),
        252 => Some("VarI1FromDisp"),
        253 => Some("VarI1FromBool"),
        254 => Some("VarI1FromUI2"),
        255 => Some("VarI1FromUI4"),
        256 => Some("VarI1FromDec"),
        257 => Some("VarUI2FromUI1"),
        258 => Some("VarUI2FromI2"),
        259 => Some("VarUI2FromI4"),
        260 => Some("VarUI2FromR4"),
        261 => Some("VarUI2FromR8"),
        262 => Some("VarUI2FromDate"),
        263 => Some("VarUI2FromCy"),
        264 => Some("VarUI2FromStr"),
        265 => Some("VarUI2FromDisp"),
        266 => Some("VarUI2FromBool"),
        267 => Some("VarUI2FromI1"),
        268 => Some("VarUI2FromUI4"),
        269 => Some("VarUI2FromDec"),
        270 => Some("VarUI4FromUI1"),
        271 => Some("VarUI4FromI2"),
        272 => Some("VarUI4FromI4"),
        273 => Some("VarUI4FromR4"),
        274 => Some("VarUI4FromR8"),
        275 => Some("VarUI4FromDate"),
        276 => Some("VarUI4FromCy"),
        277 => Some("VarUI4FromStr"),
        278 => Some("VarUI4FromDisp"),
        279 => Some("VarUI4FromBool"),
        280 => Some("VarUI4FromI1"),
        281 => Some("VarUI4FromUI2"),
        282 => Some("VarUI4FromDec"),
        283 => Some("BSTR_UserSize"),
        284 => Some("BSTR_UserMarshal"),
        285 => Some("BSTR_UserUnmarshal"),
        286 => Some("BSTR_UserFree"),
        287 => Some("VARIANT_UserSize"),
        288 => Some("VARIANT_UserMarshal"),
        289 => Some("VARIANT_UserUnmarshal"),
        290 => Some("VARIANT_UserFree"),
        291 => Some("LPSAFEARRAY_UserSize"),
        292 => Some("LPSAFEARRAY_UserMarshal"),
        293 => Some("LPSAFEARRAY_UserUnmarshal"),
        294 => Some("LPSAFEARRAY_UserFree"),
        295 => Some("LPSAFEARRAY_Size"),
        296 => Some("LPSAFEARRAY_Marshal"),
        297 => Some("LPSAFEARRAY_Unmarshal"),
        298 => Some("VarDecCmpR8"),
        299 => Some("VarCyAdd"),
        300 => Some("DllUnregisterServer"),
        301 => Some("OACreateTypeLib2"),
        303 => Some("VarCyMul"),
        304 => Some("VarCyMulI4"),
        305 => Some("VarCySub"),
        306 => Some("VarCyAbs"),
        307 => Some("VarCyFix"),
        308 => Some("VarCyInt"),
        309 => Some("VarCyNeg"),
        310 => Some("VarCyRound"),
        311 => Some("VarCyCmp"),
        312 => Some("VarCyCmpR8"),
        313 => Some("VarBstrCat"),
        314 => Some("VarBstrCmp"),
        315 => Some("VarR8Pow"),
        316 => Some("VarR4CmpR8"),
        317 => Some("VarR8Round"),
        318 => Some("VarCat"),
        319 => Some("VarDateFromUdateEx"),
        322 => Some("GetRecordInfoFromGuids"),
        323 => Some("GetRecordInfoFromTypeInfo"),
        325 => Some("SetVarConversionLocaleSetting"),
        326 => Some("GetVarConversionLocaleSetting"),
        327 => Some("SetOaNoCache"),
        329 => Some("VarCyMulI8"),
        330 => Some("VarDateFromUdate"),
        331 => Some("VarUdateFromDate"),
        332 => Some("GetAltMonthNames"),
        333 => Some("VarI8FromUI1"),
        334 => Some("VarI8FromI2"),
        335 => Some("VarI8FromR4"),
        336 => Some("VarI8FromR8"),
        337 => Some("VarI8FromCy"),
        338 => Some("VarI8FromDate"),
        339 => Some("VarI8FromStr"),
        340 => Some("VarI8FromDisp"),
        341 => Some("VarI8FromBool"),
        342 => Some("VarI8FromI1"),
        343 => Some("VarI8FromUI2"),
        344 => Some("VarI8FromUI4"),
        345 => Some("VarI8FromDec"),
        346 => Some("VarI2FromI8"),
        347 => Some("VarI2FromUI8"),
        348 => Some("VarI4FromI8"),
        349 => Some("VarI4FromUI8"),
        360 => Some("VarR4FromI8"),
        361 => Some("VarR4FromUI8"),
        362 => Some("VarR8FromI8"),
        363 => Some("VarR8FromUI8"),
        364 => Some("VarDateFromI8"),
        365 => Some("VarDateFromUI8"),
        366 => Some("VarCyFromI8"),
        367 => Some("VarCyFromUI8"),
        368 => Some("VarBstrFromI8"),
        369 => Some("VarBstrFromUI8"),
        370 => Some("VarBoolFromI8"),
        371 => Some("VarBoolFromUI8"),
        372 => Some("VarUI1FromI8"),
        373 => Some("VarUI1FromUI8"),
        374 => Some("VarDecFromI8"),
        375 => Some("VarDecFromUI8"),
        376 => Some("VarI1FromI8"),
        377 => Some("VarI1FromUI8"),
        378 => Some("VarUI2FromI8"),
        379 => Some("VarUI2FromUI8"),
        401 => Some("OleLoadPictureEx"),
        402 => Some("OleLoadPictureFileEx"),
        411 => Some("SafeArrayCreateVector"),
        412 => Some("SafeArrayCopyData"),
        413 => Some("VectorFromBstr"),
        414 => Some("BstrFromVector"),
        415 => Some("OleIconToCursor"),
        416 => Some("OleCreatePropertyFrameIndirect"),
        417 => Some("OleCreatePropertyFrame"),
        418 => Some("OleLoadPicture"),
        419 => Some("OleCreatePictureIndirect"),
        420 => Some("OleCreateFontIndirect"),
        421 => Some("OleTranslateColor"),
        422 => Some("OleLoadPictureFile"),
        423 => Some("OleSavePictureFile"),
        424 => Some("OleLoadPicturePath"),
        425 => Some("VarUI4FromI8"),
        426 => Some("VarUI4FromUI8"),
        427 => Some("VarI8FromUI8"),
        428 => Some("VarUI8FromI8"),
        429 => Some("VarUI8FromUI1"),
        430 => Some("VarUI8FromI2"),
        431 => Some("VarUI8FromR4"),
        432 => Some("VarUI8FromR8"),
        433 => Some("VarUI8FromCy"),
        434 => Some("VarUI8FromDate"),
        435 => Some("VarUI8FromStr"),
        436 => Some("VarUI8FromDisp"),
        437 => Some("VarUI8FromBool"),
        438 => Some("VarUI8FromI1"),
        439 => Some("VarUI8FromUI2"),
        440 => Some("VarUI8FromUI4"),
        441 => Some("VarUI8FromDec"),
        442 => Some("RegisterTypeLibForUser"),
        443 => Some("UnRegisterTypeLibForUser"),
        _ => None,
    }
}

/// Convert ordinal number to function name for wsock32.dll and ws2_32.dll.
fn wsock32_ord_to_name(ordinal: u16) -> Option<&'static str> {
    match ordinal {
        1 => Some("accept"),
        2 => Some("bind"),
        3 => Some("closesocket"),
        4 => Some("connect"),
        5 => Some("setpeername"),
        6 => Some("setsockname"),
        7 => Some("setsockopt"),
        8 => Some("htonl"),
        9 => Some("htons"),
        10 => Some("ioctlsocket"),
        11 => Some("inet_addr"),
        12 => Some("inet_ntoa"),
        13 => Some("listen"),
        14 => Some("ntohl"),
        15 => Some("ntohs"),
        16 => Some("recv"),
        17 => Some("recvfrom"),
        18 => Some("select"),
        19 => Some("send"),
        20 => Some("sendto"),
        21 => Some("setsockopt"),
        22 => Some("shutdown"),
        23 => Some("socket"),
        24 => Some("GetAddrInfoW"),
        25 => Some("GetNameInfoW"),
        26 => Some("WSApSetPostRoutine"),
        27 => Some("FreeAddrInfoW"),
        28 => Some("WPUCompleteOverlappedRequest"),
        29 => Some("WSAAccept"),
        30 => Some("WSAAddressToStringA"),
        31 => Some("WSAAddressToStringW"),
        32 => Some("WSACloseEvent"),
        33 => Some("WSAConnect"),
        34 => Some("WSACreateEvent"),
        35 => Some("WSADuplicateSocketA"),
        36 => Some("WSADuplicateSocketW"),
        37 => Some("WSAEnumNameSpaceProvidersA"),
        38 => Some("WSAEnumNameSpaceProvidersW"),
        39 => Some("WSAEnumNetworkEvents"),
        40 => Some("WSAEnumProtocolsA"),
        41 => Some("WSAEnumProtocolsW"),
        42 => Some("WSAEventSelect"),
        43 => Some("WSAGetOverlappedResult"),
        44 => Some("WSAGetQOSByName"),
        45 => Some("WSAGetServiceClassInfoA"),
        46 => Some("WSAGetServiceClassInfoW"),
        47 => Some("WSAGetServiceClassNameByClassIdA"),
        48 => Some("WSAGetServiceClassNameByClassIdW"),
        49 => Some("WSAHtonl"),
        50 => Some("WSAHtons"),
        51 => Some("gethostbyaddr"),
        52 => Some("gethostbyname"),
        53 => Some("getprotobyname"),
        54 => Some("getprotobynumber"),
        55 => Some("getservbyname"),
        56 => Some("getservbyport"),
        57 => Some("gethostname"),
        58 => Some("WSAInstallServiceClassA"),
        59 => Some("WSAInstallServiceClassW"),
        60 => Some("WSAIoctl"),
        61 => Some("WSAJoinLeaf"),
        62 => Some("WSALookupServiceBeginA"),
        63 => Some("WSALookupServiceBeginW"),
        64 => Some("WSALookupServiceEnd"),
        65 => Some("WSALookupServiceNextA"),
        66 => Some("WSALookupServiceNextW"),
        67 => Some("WSANSPIoctl"),
        68 => Some("WSANtohl"),
        69 => Some("WSANtohs"),
        70 => Some("WSAProviderConfigChange"),
        71 => Some("WSARecv"),
        72 => Some("WSARecvDisconnect"),
        73 => Some("WSARecvFrom"),
        74 => Some("WSARemoveServiceClass"),
        75 => Some("WSAResetEvent"),
        76 => Some("WSASend"),
        77 => Some("WSASendDisconnect"),
        78 => Some("WSASendTo"),
        79 => Some("WSASetEvent"),
        80 => Some("WSASetServiceA"),
        81 => Some("WSASetServiceW"),
        82 => Some("WSASocketA"),
        83 => Some("WSASocketW"),
        84 => Some("WSAStringToAddressA"),
        85 => Some("WSAStringToAddressW"),
        86 => Some("WSAWaitForMultipleEvents"),
        87 => Some("WSCDeinstallProvider"),
        88 => Some("WSCEnableNSProvider"),
        89 => Some("WSCEnumProtocols"),
        90 => Some("WSCGetProviderPath"),
        91 => Some("WSCInstallNameSpace"),
        92 => Some("WSCInstallProvider"),
        93 => Some("WSCUnInstallNameSpace"),
        94 => Some("WSCUpdateProvider"),
        95 => Some("WSCWriteNameSpaceOrder"),
        96 => Some("WSCWriteProviderOrder"),
        97 => Some("freeaddrinfo"),
        98 => Some("getaddrinfo"),
        99 => Some("getnameinfo"),
        101 => Some("WSAAsyncSelect"),
        102 => Some("WSAAsyncGetHostByAddr"),
        103 => Some("WSAAsyncGetHostByName"),
        104 => Some("WSAAsyncGetProtoByNumber"),
        105 => Some("WSAAsyncGetProtoByName"),
        106 => Some("WSAAsyncGetServByPort"),
        107 => Some("WSAAsyncGetServByName"),
        108 => Some("WSACancelAsyncRequest"),
        109 => Some("WSASetBlockingHook"),
        110 => Some("WSAUnhookBlockingHook"),
        111 => Some("WSAGetLastError"),
        112 => Some("WSASetLastError"),
        113 => Some("WSACancelBlockingCall"),
        114 => Some("WSAIsBlocking"),
        115 => Some("WSAStartup"),
        116 => Some("WSACleanup"),
        151 => Some("__WSAFDIsSet"),
        500 => Some("WEP"),
        _ => None,
    }
}
