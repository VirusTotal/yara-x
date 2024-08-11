use std::cell::OnceCell;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::default::Default;
use std::iter::zip;
use std::mem;
use std::str::{from_utf8, FromStr};
use std::sync::OnceLock;

use bstr::{BStr, ByteSlice};
use digest;
use itertools::Itertools;
use memchr::memmem;
use nom::branch::{alt, permutation};
use nom::bytes::complete::{take, take_till};
use nom::combinator::{cond, consumed, iterator, map, opt, success, verify};
use nom::error::ErrorKind;
use nom::multi::{
    count, fold_many0, fold_many1, length_data, many0, many1, many_m_n,
};
use nom::number::complete::{le_u16, le_u32, le_u64, u8};
use nom::sequence::tuple;
use nom::{Err, IResult, Parser, ToUsize};
use protobuf::{EnumOrUnknown, MessageField};

use crate::modules::pe::authenticode::{
    AuthenticodeHasher, AuthenticodeParser, AuthenticodeSignature,
};
use crate::modules::pe::rva2off;
use crate::modules::protos;

type Error<'a> = nom::error::Error<&'a [u8]>;

/// Tuple that contains a DLL name and a vector with functions imported from
/// that DLL.
type DllImports<'a> = Vec<(&'a str, Vec<ImportedFunc>)>;

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
    /// is called for the first time. The `u32` in the tuple is the resources
    /// timestamp.
    resources: OnceCell<Option<(ResourceDir, Vec<Resource<'a>>)>>,

    /// PE authenticode signatures.
    signatures: OnceCell<Option<Vec<AuthenticodeSignature<'a>>>>,

    /// PE directory entries. Directory entries are parsed lazily when
    /// [`PE::get_dir_entries`] is called for the first time.
    dir_entries: OnceCell<Option<Vec<DirEntry>>>,

    /// Path to PDB file containing debug information for the PE.
    pdb_path: OnceCell<Option<&'a [u8]>>,

    /// Vector with the DLLs imported by this PE file. Each item in the vector
    /// is a tuple composed of a DLL name and a vector of [`ImportedFunc`] that
    /// contains information about each function imported from the DLL. The
    /// vector can contain multiple entries for the same DLL, each with a
    /// subset of the functions imported by from that DLL.
    imports: OnceCell<Option<DllImports<'a>>>,

    /// Similar to `imports` but contains the delayed imports.
    delayed_imports: OnceCell<Option<DllImports<'a>>>,

    /// Export information about this PE file.
    exports: OnceCell<Option<ExportInfo<'a>>>,

    /// DOS header already parsed.
    pub dos_hdr: DOSHeader,

    /// PE header already parsed.
    pub pe_hdr: PEHeader,

    /// PE optional header already parsed.
    pub optional_hdr: OptionalHeader,
}

impl AuthenticodeHasher for PE<'_> {
    /// Compute an Authenticode hash for this PE file.
    ///
    /// The Authenticode covers all the data in the PE file except:
    ///
    /// * The checksum in the PE header
    /// * The security entry in the data directory (which points to the certificate table)
    /// * The certificate table.
    ///
    /// The algorithm is described in [1] and [2].
    ///
    /// [1]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#process-for-generating-the-authenticode-pe-image-hash
    /// [2]: https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
    fn hash(&self, digest: &mut dyn digest::Update) -> Option<()> {
        // Offset within the PE file where the checksum field is located. The
        // checksum is skipped while computing the digest.
        let checksum_offset = self.dos_stub.len()
            + Self::SIZE_OF_PE_SIGNATURE
            + Self::SIZE_OF_FILE_HEADER
            + 64_usize;

        // Offset of the security entry in the data directory. This entry is skipped
        // while computing the digest.
        let security_data_offset = self.dos_stub.len()
            + Self::SIZE_OF_PE_SIGNATURE
            + Self::SIZE_OF_FILE_HEADER
            + if self.optional_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC
            {
                Self::SIZE_OF_OPT_HEADER_64
            } else {
                Self::SIZE_OF_OPT_HEADER_32
            }
            + Self::SIZE_OF_DIR_ENTRY * Self::IMAGE_DIRECTORY_ENTRY_SECURITY;

        let (_, cert_table_size, _) = self
            .get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_SECURITY, true)?;

        // Hash from start of the file to the checksum.
        digest.update(self.data.get(0..checksum_offset)?);

        // Hash from the end of the checksum to the start of the security entry
        // in the data directory.
        digest.update(self.data.get(
            checksum_offset + mem::size_of::<u32>()..security_data_offset,
        )?);

        // Hash from the end of the security entry in the data directory to the
        // end of the PE header.
        digest.update(self.data.get(
            security_data_offset + Self::SIZE_OF_DIR_ENTRY
                ..self.optional_hdr.size_of_headers as usize,
        )?);

        // Sections must be sorted by `raw_data_offset`.
        let sections = self
            .sections
            .iter()
            .sorted_unstable_by_key(|section| section.raw_data_offset);

        let mut sum_of_bytes_hashed =
            self.optional_hdr.size_of_headers as usize;

        // Hash each section's data.
        for section in sections {
            let section_start = section.raw_data_offset as usize;
            let section_size = section.raw_data_size as usize;
            let section_end = section_start.saturating_add(section_size);
            let section_bytes = self.data.get(section_start..section_end)?;

            digest.update(section_bytes);

            sum_of_bytes_hashed =
                sum_of_bytes_hashed.checked_add(section_size)?;
        }

        let extra_hash_len = self
            .data
            .len()
            .checked_sub(cert_table_size as usize)?
            .checked_sub(sum_of_bytes_hashed)?;

        digest.update(self.data.get(
            sum_of_bytes_hashed
                ..sum_of_bytes_hashed.checked_add(extra_hash_len)?,
        )?);

        Some(())
    }
}

impl<'a> PE<'a> {
    /// Given the content of PE file, parses it and returns a [`PE`] object
    /// representing the file.
    pub fn parse(data: &'a [u8]) -> Result<Self, Err<Error<'a>>> {
        // Parse the MZ header.
        let (_, dos_hdr) = Self::parse_dos_header(data)?;

        // The PE header starts at the offset indicated by `dos_hdr.e_lfanew`.
        // Everything between offset 0 and `dos_hdr.e_lfanew` is stored in the
        // `dos_stub` slice, including the DOS header, the MS-DOS stub and the
        // rich signature.
        let (pe, dos_stub) = take(dos_hdr.e_lfanew)(data)?;

        // Parse the PE header (IMAGE_FILE_HEADER)
        let (optional_hdr, pe_hdr) = Self::parse_pe_header(pe)?;

        // Parse the PE optional header (IMAGE_OPTIONAL_HEADER).
        let (directory, optional_hdr) =
            Self::parse_opt_header()(optional_hdr).unwrap_or_default();

        // The string table is located right after the COFF symbol table.
        let string_table_offset = pe_hdr.symbol_table_offset.saturating_add(
            pe_hdr.number_of_symbols.saturating_mul(Self::SIZE_OF_SYMBOL),
        );

        let string_table = data.get(string_table_offset as usize..);

        // Parse the section table. The section table is located right after
        // NT headers, which starts at pe_hdr and is composed of the PE
        // signature, the file header, and a variable-length optional header.
        let sections = if let Some(section_table) = pe.get(
            Self::SIZE_OF_PE_SIGNATURE
                + Self::SIZE_OF_FILE_HEADER
                + pe_hdr.size_of_optional_header as usize..,
        ) {
            many_m_n(
                // Parse at least one section.
                1,
                // The number of sections is capped to MAX_PE_SECTIONS.
                usize::min(
                    pe_hdr.number_of_sections as usize,
                    Self::MAX_PE_SECTIONS,
                ),
                // The section parser needs the string table for resolving
                // some section names.
                Self::parse_section(string_table),
            )(section_table)
            .map(|(_, sections)| sections)
            .ok()
        } else {
            None
        };

        Ok(PE {
            data,
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
    /// An RVA is an offset relative to the base address of the executable
    /// program. The PE format uses RVAs in multiple places and sometimes
    /// is necessary to covert the RVA to a file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        rva2off::rva_to_offset(
            rva,
            self.sections.as_slice(),
            self.optional_hdr.file_alignment,
            self.optional_hdr.section_alignment,
        )
    }

    /// Given an RVA, returns a byte slice with the content of the PE that
    /// goes from that RVA to the end of the file.
    #[inline]
    pub fn data_at_rva(&self, rva: u32) -> Option<&'a [u8]> {
        let offset = self.rva_to_offset(rva)?;
        self.data.get(offset as usize..)
    }

    /// Given an RVA, returns a byte slice with the content of the PE that
    /// goes from that RVA to the end of the file, or to the given size,
    /// whatever comes first.
    #[inline]
    pub fn data_at_rva_with_size(
        &self,
        rva: u32,
        size: usize,
    ) -> Option<&'a [u8]> {
        let start = self.rva_to_offset(rva)? as usize;
        let end = min(start.saturating_add(size), self.data.len());
        self.data.get(start..end)
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
    pub fn get_pdb_path(&self) -> Option<&'a [u8]> {
        *self.pdb_path.get_or_init(|| self.parse_dbg())
    }

    /// Returns a slice of [`Resource`] structures, one per each resource
    /// declared in the PE file.
    pub fn get_resources(&self) -> &[Resource<'a>] {
        // Resources are parsed only the first time this function is called,
        // in subsequent calls the already parsed resources are returned.
        self.resources
            .get_or_init(|| self.parse_resources())
            .as_ref()
            .map(|(_dir, resources)| resources.as_slice())
            .unwrap_or_default()
    }

    /// Get the directory entry corresponding to the PE resources.
    pub fn get_resource_dir(&self) -> Option<&ResourceDir> {
        // Resources are parsed only the first time this function is called,
        // in subsequent calls the already parsed resources are returned.
        self.resources
            .get_or_init(|| self.parse_resources())
            .as_ref()
            .map(|(dir, _resources)| dir)
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

    /// Returns the RVA, size and data associated to a given directory entry.
    ///
    /// The returned tuple is `(addr, size, data)`, where `addr` and `size` are
    /// the ones indicated in the directory entry, and `data` is a slice that
    /// contains the file's content from that RVA to the end of the file if
    /// `strict_size` is false. Otherwise, the slice will be limited to the
    /// size indicated in the directory entry.
    pub fn get_dir_entry_data(
        &self,
        index: usize,
        strict_size: bool,
    ) -> Option<(u32, u32, &'a [u8])> {
        // Nobody should call this function with an index greater
        // than MAX_DIR_ENTRIES.
        debug_assert!(index < Self::MAX_DIR_ENTRIES);

        // In theory, `index` should be lower than `number_of_rva_and_sizes`,
        // however, we don't enforce it because some PE files have a
        // `number_of_rva_and_sizes` values lower than the actual
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

        // The IMAGE_DIRECTORY_ENTRY_SECURITY is the only one where the `addr`
        // field is not an RVA, but a file offset, so we don't need to convert
        // it to offset.
        let start = if index == Self::IMAGE_DIRECTORY_ENTRY_SECURITY {
            dir_entry.addr
        } else {
            self.rva_to_offset(dir_entry.addr)?
        };

        let end = if strict_size {
            min(self.data.len(), start.saturating_add(dir_entry.size) as usize)
        } else {
            self.data.len()
        };

        let data = self.data.get(start as usize..end)?;

        Some((dir_entry.addr, dir_entry.size, data))
    }

    /// Returns information about the functions imported by this PE file.
    ///
    /// The result is an iterator that yields tuples. The first item in the
    /// tuple is a DLL from which the PE imports functions, and the second
    /// item is a slice of [`ImportedFunc`] structures, one per function
    /// imported from that DLL.
    pub fn get_imports(
        &self,
    ) -> Option<impl Iterator<Item = (&'a str, &[ImportedFunc])>> {
        let imports =
            self.imports.get_or_init(|| self.parse_imports()).as_ref()?;

        Some(imports.iter().map(|(name, funcs)| (*name, funcs.as_slice())))
    }

    /// Similar to [`get_imports`] but returns delayed imports.
    ///
    /// A delayed import is a hybrid approach between an implicit import and
    /// explicitly importing APIs via LoadLibrary and GetProcAddress. Delayed
    /// imports are not resolved when the PE is loaded, they are resolved the
    /// first time the imported function is called.
    pub fn get_delayed_imports(
        &self,
    ) -> Option<impl Iterator<Item = (&'a str, &[ImportedFunc])>> {
        let delayed_imports = self
            .delayed_imports
            .get_or_init(|| self.parse_delayed_imports())
            .as_ref()?;

        Some(
            delayed_imports
                .iter()
                .map(|(name, funcs)| (*name, funcs.as_slice())),
        )
    }

    /// Returns information about the functions exported by this PE.
    pub fn get_exports(&self) -> Option<&ExportInfo<'a>> {
        self.exports.get_or_init(|| self.parse_exports()).as_ref()
    }

    /// Returns the authenticode signatures in this PE.
    pub fn get_signatures(&self) -> &[AuthenticodeSignature<'a>] {
        self.signatures
            .get_or_init(|| self.parse_signatures())
            .as_ref()
            .map(|s| s.as_slice())
            .unwrap_or(&[])
    }
}

impl<'a> PE<'a> {
    pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
    pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

    pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
    pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
    pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
    pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
    pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

    const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

    const RICH_TAG: &'static [u8] = &[0x52_u8, 0x69, 0x63, 0x68];
    const DANS_TAG: u32 = 0x536e6144;

    // size of PE signature (PE\0\0).
    const SIZE_OF_PE_SIGNATURE: usize = 4;

    // size of IMAGE_FILE_HEADER
    const SIZE_OF_FILE_HEADER: usize = 20;

    // size of IMAGE_OPTIONAL_HEADER for 32-bit files.
    // Without data directory entries.
    const SIZE_OF_OPT_HEADER_32: usize = 96;

    // size of IMAGE_OPTIONAL_HEADER for 64-bit files.
    // Without data directory entries.
    const SIZE_OF_OPT_HEADER_64: usize = 112;

    const SIZE_OF_DIR_ENTRY: usize = 8;
    const SIZE_OF_SYMBOL: u32 = 18;

    const MAX_PE_SECTIONS: usize = 96;
    const MAX_PE_IMPORTS: usize = 16384;
    const MAX_PE_EXPORTS: usize = 16384;
    const MAX_PE_RESOURCES: usize = 65536;
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
                le_u16, // magic
                u8,     // major_linker_ver
                u8,     // minor_linker_ver
                le_u32, // size_of_code
                le_u32, // size_of_initialized_data
                le_u32, // size_of_uninitialized_data
                le_u32, // entry_point
                le_u32, // base_of_code
            ))(input)?;

            // opt_hdr.magic should be either IMAGE_NT_OPTIONAL_HDR32_MAGIC
            // or IMAGE_NT_OPTIONAL_HDR64_MAGIC, but when the file is corrupt
            // and opt_hdr.magic is something else, we assume that the file
            // is a 32-bit PE for the purpose of continuing parsing the
            // remaining fields, because that's what YARA does. That's the
            // case of:
            // 3df167b04c52b47ae634b8114671ad3b7bf4e8af62a38a3d4bc0903f474ae2d9

            (
                remainder,
                (
                    base_of_data, // only in 32-bits PE
                    image_base32, // only in 32-bits PE
                    image_base64, // only in 64-bits PE
                ),
            ) = tuple((
                cond(
                    opt_hdr.magic != Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC,
                    le_u32,
                ),
                cond(
                    opt_hdr.magic != Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC,
                    le_u32,
                ),
                cond(
                    opt_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC,
                    le_u64,
                ),
            ))(remainder)?;

            opt_hdr.base_of_data = base_of_data;
            opt_hdr.image_base = image_base32
                .map(|i| i as u64)
                .or(image_base64)
                .unwrap_or_default();

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
                uint(opt_hdr.magic != Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC),
                uint(opt_hdr.magic != Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC),
                uint(opt_hdr.magic != Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC),
                uint(opt_hdr.magic != Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC),
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
            // encrypting the Rich data.
            let (remainder, key) = le_u32(&input[rich_tag_pos + 4..])?;

            // Search for the "DanS" tag that indicates the start of the rich
            // data. This tag appears encrypted with the XOR key.
            let dans_tag = key ^ Self::DANS_TAG;

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

            // Parse the rich data. Some tools, like `pefile`, assume that
            // the three DWORD values right after the "DanS" tag (12 bytes in
            // total), must be copies of the XOR key, and make a validation
            // based on that assumption, to the extent of considering the
            // whole rich header invalid if that condition is not met. The C
            // implementation of YARA inherited this behaviour.
            //
            // However, everything indicates that these values are just
            // padding. As the padding is initially filled with zeros, when
            // the XOR key is applied, their values become the key itself.
            //
            // I'm not making any assumptions about the values in the padding
            // bytes. The rich is header is considered valid no matter what
            // those 12 bytes contain.
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

    pub fn parse_dir_entry(input: &[u8]) -> IResult<&[u8], DirEntry> {
        map(tuple((le_u32, le_u32)), |(addr, size)| DirEntry { addr, size })(
            input,
        )
    }

    fn parse_rsrc_dir(input: &[u8]) -> IResult<&[u8], ResourceDir> {
        map(
            tuple((
                // characteristics must be 0
                verify(le_u32, |characteristics| *characteristics == 0),
                le_u32,                          // timestamp
                le_u16,                          // major_version
                le_u16,                          // minor_version
                verify(le_u16, |n| *n <= 32768), // number_of_named_entries
                verify(le_u16, |n| *n <= 32768), // number_of_id_entries
            )),
            |(
                _characteristics,
                timestamp,
                major_version,
                minor_version,
                number_of_named_entries,
                number_of_id_entries,
            )| {
                ResourceDir {
                    timestamp,
                    major_version,
                    minor_version,
                    number_of_entries: number_of_id_entries as usize
                        + number_of_named_entries as usize,
                }
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
            // name is found. The name is a UTF-16LE string that starts with an
            // u16 containing its length in characters. If the high bit is not
            // set then `name_or_id` is just the resource ID.
            let id = if name_or_id & 0x80000000 != 0 {
                resource_section
                    .get((name_or_id & 0x7FFFFFFF) as usize..)
                    .and_then(|string| {
                        length_data(map(
                            // any string with more than 1000 characters
                            // (2000 bytes) is ignored.
                            verify(le_u16::<&[u8], Error>, |len| *len < 1000),
                            // length from characters to bytes.
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

            Ok((
                remainder,
                ResourceDirEntry { is_subdir, id, offset: offset as usize },
            ))
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

    /// Parses VERSIONINFO structures stored in resources.
    ///
    /// Each PE file can contain one or more resources containing a VERSIONINFO
    /// structure. This functions parses all of them.
    ///
    /// VERSIONINFO is tree-like structure where each node has a key, an
    /// optional value, and possible a certain number of children. Here is an
    /// example of how this structure typically looks like:
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
        let result = self
            .get_resources()
            .iter()
            // Use only the resources that contain version information, and
            // get the resource data.
            .filter_map(|resource| {
                if resource.type_id
                    == ResourceId::Id(
                        protos::pe::ResourceType::RESOURCE_TYPE_VERSION as u32,
                    )
                {
                    self.data.get(resource.offset? as usize..)
                } else {
                    None
                }
            })
            // Parse each resource that contain version info, appending the
            // (key, value) pairs to `result`.
            .fold(Vec::new(), |mut result, version_info_raw| {
                let version_info = Self::parse_info_with_key(
                    "VS_VERSION_INFO",
                    version_info_raw,
                    Some(tuple((
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
                    ))),
                    // Possible children are StringFileInfo and VarFileInfo
                    // structures. Both are optional, and they can appear in any
                    // order. Usually StringFileInfo appears first, but
                    // 09e7d832320e51bcc80b9aecde2a4135267a9b0156642a9596a62e85c9998cc9
                    // is an example where VarFileInfo appears first.
                    permutation((
                        opt(Self::parse_var_file_info),
                        opt(Self::parse_string_file_info),
                    )),
                );

                if let Ok((_, (_, _, (_, Some(strings))))) = version_info {
                    result.extend(strings);
                }

                result
            });

        if result.is_empty() {
            return None;
        }

        Some(result)
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
                    // StringFileInfo doesn't have any value.
                    None::<Box<dyn Parser<&[u8], (), Error>>>,
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
                    // VarFileInfo doesn't have any value.
                    None::<Box<dyn Parser<&[u8], (), Error>>>,
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
                // StringTable doesn't have any value.
                None::<Box<dyn Parser<&[u8], (), Error>>>,
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
                Some(utf16_le_string()),
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
        value_parser: Option<F>,
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
    ///             characters, not bytes. However there are PE files that
    ///             don't respect this, and value_len is always in bytes
    ///             regardless of the type of value.
    /// padding1  - 0 or more bytes that align the next field to a 32-bits
    ///             boundary
    /// children  - data that corresponds to the children of this structure
    /// ```
    ///
    /// This function returns a parser for one of these structures, where the
    /// parser for the value and the children are passed as arguments. The
    /// value parser is optional, if not provided, the value will be handled
    /// as a zero-length value regardless of what the `value_len` field
    /// says.
    fn parse_info<'b, F, G, V, C>(
        mut value_parser: Option<F>,
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
            let length = Self::round_up::<4, _>(length);

            // Read the structure's bytes.
            let (remainder, structure) = take(length)(input)?;

            // Parse the structure's first fields.
            let (_, (consumed, (_, value_len, _type, key))) =
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
            let alignment = Self::round_up::<4, _>(consumed.len());

            // Then take `alignment` bytes from the start of the structure. The
            // remaining bytes contain the value and children.
            let (value_and_children, _) = take(alignment)(structure)?;

            // The value will be parsed only if `value_parser` it not `None` and
            // `value_len` is larger than zero. If `value_parser` is `None` the
            // value will be considered as a zero-length value, regardless of
            // what `value_len` says. This useful for parsing some PE files that
            // have a `value_len` larger than zero in structures that doesn't
            // actually have any value. For instance, the StringFileInfo structure
            // in 7aa3e6d7b3f2fcab5c9432cb6d8db094cc1df1b4ed11ff7a386662c4914a1eb3
            // has a non-zero `value_len`.
            let (raw_children, value) = match &mut value_parser {
                Some(value_parser) if value_len > 0 => {
                    // The PE specification seems to suggest that when `type` is 1,
                    // the value is a text and `value_length` indicates its size
                    // in UTF-16 characters, but it's not clear whether the size
                    // includes the null-terminator or not. In some files like
                    // 0ba6042247d90a187919dd88dc2d55cd882c80e5afc511c4f7b2e0e193968f7f
                    // the `value_length` is the number of UTF-16 characters,
                    // including the null terminator. But in some other cases, like
                    // abeef1c9452835ba856c3bef32657076b7757c21e9f5c78f6336cfedc87d0b46
                    // it doesn't include the null terminator.
                    //
                    // Also, there are many PE files for which `value_length` is
                    // in bytes, even if `type` is 1, that's the case of:
                    // db6a9934570fa98a93a979e7e0e218e0c9710e5a787b18c6948f2eedd9338984
                    //
                    // To make things even worse, there are files where `value_length`
                    // is incorrect, like in:
                    // 8daffcac250ed6927e3d600e6bf14ea1d38dd6237f95222e6582495108b63971
                    //
                    // For all these reasons `value_length` is not taken into account
                    // and the whole slice contains the value and the children that
                    // follow (if any) is passed to the value parser, letting the
                    // parser determine which is the actual length of the value.
                    match value_parser.parse(value_and_children) {
                        Ok((raw_children, value)) => {
                            (raw_children, Some(value))
                        }
                        Err(_) => (value_and_children, None),
                    }
                }
                _ => (value_and_children, None),
            };

            let (_, children) = children_parser.parse(raw_children)?;

            Ok((remainder, (key, value, children)))
        }
    }

    /// Round up a `value` to the `ROUND_TO` byte boundary.
    fn round_up<const ROUND_TO: usize, O: ToUsize>(value: O) -> usize {
        value.to_usize().div_ceil(ROUND_TO) * ROUND_TO
    }

    /// Parses the PE resources.
    ///
    /// Resources are stored in tree structure with three levels. Non-leaf
    /// nodes are represented by IMAGE_RESOURCE_DIRECTORY structures, where the
    /// root of the tree is the IMAGE_RESOURCE_DIRECTORY located at the point
    /// indicated by the IMAGE_DIRECTORY_ENTRY_RESOURCE entry in the PE
    /// directory.
    ///
    /// Right after each IMAGE_RESOURCE_DIRECTORY, there's a sequence of
    /// IMAGE_RESOURCE_DIRECTORY_ENTRY structures, where each of this entries
    /// can correspond to leaf in the tree (i.e: an actual resource) or a
    /// subdirectory.
    ///
    /// If the entry corresponds to a subdirectory, its offset points to
    /// another IMAGE_RESOURCE_DIRECTORY structure, which in turns is
    /// followed by more IMAGE_DIRECTORY_ENTRY_RESOURCE. If the entry
    /// corresponds to leaf, its offset points to the resource data. The
    /// structure of this data depends on the type of the resource. But we
    /// don't parse the resource themselves, only the resource tree.
    ///
    /// This function performs a BFS traversal over the resource tree, creating
    /// a list of resources with one entry per tree leaf. The three levels in
    /// the tree correspond to resource types, resources, and language. That
    /// means that at the top level we have one entry per resource type: icon,
    /// string table, menu, etc. The children of each type correspond to
    /// individual resources of that type, and the children of each individual
    /// resource represent the resource in a specific language.
    fn parse_resources(&self) -> Option<(ResourceDir, Vec<Resource<'a>>)> {
        let (_, _, rsrc_section) = self
            .get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_RESOURCE, false)?;

        let mut queue = VecDeque::new();
        let mut resources = vec![];
        let mut resources_info = ResourceDir::default();

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
            let (raw_entries, rsrc_dir) = match Self::parse_rsrc_dir(rsrc_dir)
            {
                Ok(result) => result,
                Err(_) => continue,
            };

            // Parse a series of IMAGE_RESOURCE_DIRECTORY_ENTRY that come
            // right after the IMAGE_RESOURCE_DIRECTORY.
            let mut dir_entries = iterator(
                raw_entries,
                Self::parse_rsrc_dir_entry(rsrc_section),
            );

            // Entries with invalid offsets are ignored, they are a sign
            // of PE corruption.
            let dir_entries =
                dir_entries.take(rsrc_dir.number_of_entries).filter(|entry| {
                    entry.offset > 0 && entry.offset < rsrc_section.len()
                });

            if level == 0 {
                resources_info = rsrc_dir;
            }

            // Iterate over the directory entries. Each entry can be either a
            // subdirectory or a leaf.
            for dir_entry in dir_entries {
                if let Some(entry_data) = rsrc_section.get(dir_entry.offset..)
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
                        // obtained from the parent. As a sanity check we
                        // make sure that language id is lower than 0xfffff.
                        2 => match dir_entry.id {
                            ResourceId::Id(id) if id > 0xfffff => continue,
                            _ => (ids.0, ids.1, dir_entry.id),
                        },
                        // Resource trees have 3 levels at most. We must
                        // protect ourselves against corrupted or maliciously
                        // crafted files that have too many levels.
                        _ => continue,
                    };

                    if dir_entry.is_subdir {
                        queue.push_back((level + 1, ids, entry_data));
                    }
                    if let Ok((_, rsrc_entry)) =
                        Self::parse_rsrc_entry(entry_data)
                    {
                        if rsrc_entry.size > 0
                            && rsrc_entry.offset > 0
                            && (rsrc_entry.size as usize) < self.data.len()
                        {
                            resources.push(Resource {
                                type_id: ids.0,
                                rsrc_id: ids.1,
                                lang_id: ids.2,
                                // `rsrc_entry.offset` is relative to the start of
                                // the resource section, so it's actually an RVA.
                                // Here we convert it to a file offset.
                                offset: self.rva_to_offset(rsrc_entry.offset),
                                rva: rsrc_entry.offset,
                                length: rsrc_entry.size,
                            });

                            if resources.len() == Self::MAX_PE_RESOURCES {
                                return Some((resources_info, resources));
                            }
                        }
                    }
                }
            }
        }

        if resources.is_empty() {
            return None;
        }

        Some((resources_info, resources))
    }

    /// Parses the PE Authenticode signatures.
    fn parse_signatures(&self) -> Option<Vec<AuthenticodeSignature<'a>>> {
        let (_, _, cert_table) = self
            .get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_SECURITY, true)?;

        // The certificate table is an array of WIN_CERTIFICATE structures.
        let signatures = fold_many0(
            self.win_cert_parser(),
            Vec::new,
            |mut acc: Vec<_>, signatures| {
                acc.extend(signatures);
                acc
            },
        )(cert_table)
        .map(|(_, cert)| cert)
        .ok()?;

        Some(signatures)
    }

    /// Returns a parser that parses a WIN_CERTIFICATE structure.
    fn win_cert_parser(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<AuthenticodeSignature>> + '_
    {
        move |input: &'a [u8]| {
            // Parse the WIN_CERTIFICATE structure.
            let (remainder, (length, _revision, _cert_type)) =
                tuple((
                    le_u32::<&[u8], Error>, // length
                    le_u16, // revision, should be WIN_CERT_REVISION_1_0 (0x0100)
                    le_u16, // certificate type
                ))(input)?;

            // The length includes the header, compute the length of the signature.
            let signature_length: u32 =
                length.checked_sub(8).ok_or_else(|| {
                    Err::Error(Error::new(input, ErrorKind::Fail))
                })?;

            let (_, signature_data) = take(signature_length)(remainder)?;
            let (_, signatures) = self.signature_parser()(signature_data)?;

            // The next WIN_CERTIFICATE is aligned to the next 8-bytes boundary.
            let (remainder, _) = take(Self::round_up::<8, _>(length))(input)?;

            Ok((remainder, signatures))
        }
    }

    /// Returns a parser that parses the PKCS#7 blob that containing an
    /// Authenticode signature.
    fn signature_parser(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<AuthenticodeSignature>> + '_
    {
        move |input: &'a [u8]| {
            let signatures = AuthenticodeParser::parse(input, self)
                .map_err(|_| Err::Error(Error::new(input, ErrorKind::Fail)))?;
            Ok((&[], signatures))
        }
    }

    fn parse_dir_entries(&self) -> Option<Vec<DirEntry>> {
        // The number of directory entries is limited to MAX_DIR_ENTRIES.
        let num_dir_entries = usize::min(
            self.optional_hdr.number_of_rva_and_sizes as usize,
            Self::MAX_DIR_ENTRIES,
        );

        // Parse the data directory.
        count(Self::parse_dir_entry, num_dir_entries)(self.directory)
            .map(|(_, entries)| entries)
            .ok()
    }

    /// Parses the PE debug information and extracts the PDB path.
    fn parse_dbg(&self) -> Option<&'a [u8]> {
        let (_, _, dbg_section) =
            self.get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_DEBUG, true)?;

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
                    return Some(pdb_path)
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

    /// Parses PE imports.
    fn parse_imports(&self) -> Option<Vec<(&'a str, Vec<ImportedFunc>)>> {
        let (addr, _, import_data) = self
            .get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_IMPORT, false)?;

        if addr == 0 {
            return None;
        }

        self.parse_import_impl(import_data, Self::parse_import_descriptor)
    }

    /// Parses PE delayed imports.
    fn parse_delayed_imports(
        &self,
    ) -> Option<Vec<(&'a str, Vec<ImportedFunc>)>> {
        let (addr, _, import_data) = self.get_dir_entry_data(
            Self::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
            true,
        )?;

        if addr == 0 {
            return None;
        }

        self.parse_import_impl(import_data, Self::parse_delay_load_descriptor)
    }

    /// Common logic for parsing ordinary and delayed imports.
    ///
    /// Both ordinary and delayed imports follow a similar logic. Ordinary
    /// imports are described by a sequence of IMAGE_IMPORT_DESCRIPTOR
    /// structures (usually one per imported DLL), that start at the RVA
    /// indicated by the directory entry IMAGE_DIRECTORY_ENTRY_IMPORT (1).
    /// This structure has two fields (original_first_thunk and first_thunk)
    /// that point to the Import Name Table (INT) and Import Address Table
    /// (IAT) respectively. The INT and the IAT have the same number of slots,
    /// one per function imported from the DLL. The type of these slots is
    /// IMAGE_THUNK_DATA32 or IMAGE_THUNK_DATA64, depending on whether it is
    /// a 32-bits or 64-bits PE file.
    ///
    /// Delayed imports are described by IMAGE_DELAYLOAD_DESCRIPTOR structures
    /// starting at the RVA indicated by the directory entry
    /// IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (13). These structures are not
    /// equal to IMAGE_IMPORT_DESCRIPTOR, that's the first difference with
    /// respect to ordinary imports, but they also have two fields that
    /// are equivalent to original_first_thunk and first_thunk, and point to
    /// arrays equivalent to the INT and IAT.
    ///
    /// Another differences between ordinal and delayed imports is that in
    /// in delayed imports the INT and IAT can contain virtual addresses
    /// instead of relative virtual address (RVAs). Whether they contain one
    /// or the other depends on a bit in the `attributes` field in the
    /// IMAGE_DELAYLOAD_DESCRIPTOR structure.
    fn parse_import_impl<P>(
        &self,
        input: &'a [u8],
        descriptor_parser: P,
    ) -> Option<Vec<(&'a str, Vec<ImportedFunc>)>>
    where
        P: FnMut(&'a [u8]) -> IResult<&'a [u8], ImportDescriptor>,
    {
        // `optional_hdr.magic` must be either IMAGE_NT_OPTIONAL_HDR32_MAGIC
        // or IMAGE_NT_OPTIONAL_HDR64_MAGIC, but in some corrupted files it
        // is something else (like 0). That's the case of file
        // d3e606b4f1f30f3ee9f4263edb513b66ee81348ab8b56060dc05c4b0fc297f32.
        // In such cases we assume that the file is a 32-bit file, for
        // compatibility with YARA. That's why we don't use:
        //let is_32_bits =
        //  self.optional_hdr.magic == Self::IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        let is_32_bits =
            self.optional_hdr.magic != Self::IMAGE_NT_OPTIONAL_HDR64_MAGIC;

        let mut imported_funcs = Vec::new();

        // Parse import descriptors until finding one that is empty (filled
        // with null values), which indicates the end of the directory table;
        // or until `MAX_PE_IMPORTS` is reached.
        let mut import_descriptors = iterator(
            input,
            verify(descriptor_parser, |d| {
                d.name != 0
                    && (d.import_address_table != 0
                        || d.import_name_table != 0)
            }),
        );

        for mut descriptor in import_descriptors.take(Self::MAX_PE_IMPORTS) {
            // If the values in the descriptor are virtual addresses, convert
            // them to relative virtual addresses (RVAs) by subtracting the
            // image base. This only happens with 32-bits PE files, in 64-bits
            // these values are always RVAs, therefore converting the image
            // base to 32-bits it's ok.
            if descriptor.va_values {
                if let Ok(image_base) = self.optional_hdr.image_base.try_into()
                {
                    descriptor.name =
                        descriptor.name.saturating_sub(image_base);

                    descriptor.import_name_table = descriptor
                        .import_name_table
                        .saturating_sub(image_base);

                    descriptor.import_address_table = descriptor
                        .import_address_table
                        .saturating_sub(image_base);
                } else {
                    continue;
                }
            }

            let dll_name =
                if let Some(name) = self.dll_name_at_rva(descriptor.name) {
                    name
                } else {
                    continue;
                };

            // Use the INT (a.k.a: OriginalFirstThunk) if it is non-zero, but
            // fallback to using the IAT (a.k.a: FirstThunk).
            let thunks = if descriptor.import_name_table > 0 {
                self.data_at_rva(descriptor.import_name_table)
            } else {
                None
            }
            .or_else(|| self.data_at_rva(descriptor.import_address_table));

            let thunks = match thunks {
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

            let mut funcs = Vec::new();

            for (i, mut thunk) in
                &mut thunks.take(Self::MAX_PE_IMPORTS).enumerate()
            {
                // If the most significant bit is set, this is an import by
                // ordinal. The most significant bit depends on whether this
                // is a 64-bits PE.
                let import_by_ordinal = if is_32_bits {
                    thunk & 0x80000000 != 0
                } else {
                    thunk & 0x8000000000000000 != 0
                };

                // Check that thunk doesn't exceed the maximum possible value.
                // The maximum possible value occurs when the most significant
                // bit is set (import by ordinal) and the ordinal number is
                // 65535, which is the maximum possible ordinal.
                let max_thunk =
                    if is_32_bits { 0x8000ffff } else { 0x800000000000ffff };

                if thunk > max_thunk {
                    continue;
                }

                let mut func = ImportedFunc {
                    rva: descriptor.import_address_table.saturating_add(
                        (i * if is_32_bits { 4 } else { 8 }) as u32,
                    ),
                    ..Default::default()
                };

                if import_by_ordinal {
                    let ordinal = (thunk & 0xffff) as u16;
                    func.ordinal = Some(ordinal);
                    func.name = ord_to_name(dll_name, ordinal);
                } else {
                    // When descriptor values are virtual addresses, thunks are
                    // virtual addresses too and need to be converted to RVAs.
                    if descriptor.va_values {
                        thunk =
                            thunk.saturating_sub(self.optional_hdr.image_base);
                    }

                    if let Ok(rva) = TryInto::<u32>::try_into(thunk) {
                        func.name = self
                            .parse_at_rva(rva, Self::parse_import_by_name)
                            .map(|n| n.to_vec())
                            .and_then(|n| String::from_utf8(n).ok());
                    }
                }

                if func.ordinal.is_some() || func.name.is_some() {
                    funcs.push(func);
                }
            }

            if !funcs.is_empty() {
                imported_funcs.push((dll_name, funcs));
            }

            if imported_funcs.len() >= Self::MAX_PE_IMPORTS {
                break;
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
            |(original_first_thunk, _, _, name, first_thunk)| {
                ImportDescriptor {
                    va_values: false,
                    name,
                    import_name_table: original_first_thunk,
                    import_address_table: first_thunk,
                }
            },
        )(input)
    }

    fn parse_delay_load_descriptor(
        input: &[u8],
    ) -> IResult<&[u8], ImportDescriptor> {
        map(
            tuple((
                le_u32, // attributes
                le_u32, // name
                le_u32, // module_handle
                le_u32, // import_address_table
                le_u32, // import_name_table
                le_u32, // bound_import_addr_table_rva
                le_u32, // unload_information_table_rva
                le_u32, // timestamp
            )),
            |(
                attributes,
                name,
                _,
                import_address_table,
                import_name_table,
                _,
                _,
                _,
            )| {
                // `name`, `import_name_table` and `import_address_table` are
                // relative virtual addresses (RVA) when the least significant
                // bit in `attributes` is set to 1. When this bit is set to 0
                // the values are virtual addresses (absolute, not relative).
                //
                // Matt Pietrek's article "An In-Depth Look into the Win32
                // Portable Executable File Format" states:
                //
                // "In its original incarnation in Visual C++ 6.0, all
                // ImgDelayDescr fields containing addresses used virtual
                // addresses, rather than RVAs. That is, they contained actual
                // addresses where the delayload data could be found. These
                // fields are DWORDs, the size of a pointer on the x86.
                // Now fast-forward to IA-64 support. All of a sudden, 4 bytes
                // isn't enough to hold a complete address. Ooops! At this
                // point, Microsoft did the correct thing and changed the
                // fields containing addresses to RVAs"
                //
                // File that contains virtual addresses instead of RVAs:
                // 2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4
                ImportDescriptor {
                    va_values: attributes & 1 == 0,
                    name,
                    import_name_table,
                    import_address_table,
                }
            },
        )(input)
    }

    fn parse_import_by_name(input: &[u8]) -> IResult<&[u8], &[u8]> {
        map(
            tuple((
                le_u16, // hint
                verify(take_till(|c: u8| c == 0_u8), |name: &[u8]| {
                    !name.is_empty()
                }), // name
            )),
            |(_, name)| name,
        )(input)
    }

    fn parse_exports(&self) -> Option<ExportInfo<'a>> {
        let (exports_rva, exports_size, exports_data) =
            self.get_dir_entry_data(Self::IMAGE_DIRECTORY_ENTRY_EXPORT, true)?;

        if exports_rva == 0 {
            return None;
        }

        let exports_section =
            exports_rva..exports_rva.saturating_add(exports_size);

        // Parse the IMAGE_EXPORT_DIRECTORY structure.
        let (_, exports) = Self::parse_exports_dir_entry(exports_data).ok()?;

        let num_exports =
            min(exports.number_of_functions as usize, Self::MAX_PE_EXPORTS);

        let num_names =
            min(exports.number_of_names as usize, Self::MAX_PE_EXPORTS);

        // The IMAGE_EXPORT_DIRECTORY structure points to three arrays. The
        // only required array is the Export Address Table (EAT), which is an
        // array of function pointers that contain the address (RVA) of an
        // exported function. The `address_of_functions` field contains the
        // RVA for this array. There are as many exported functions as entries
        // in the `address_of_functions` array. The size of this array is
        // indicated by the `number_of_functions` field.
        //
        // The purpose of the other two arrays is associating a name to
        // the imported functions, but not all functions have an associated
        // name. Functions that are exported only by ordinal don't have an
        // associated entry in these arrays.
        //
        // Let's illustrate it with an example:
        //
        // base:  5
        // address_of_functions:     [ 0x00000011 | 0x00000022 | 0x00000033 ]
        // address_of_name_ordinals: [     0x0000 |     0x0002 |     0x0001 ]
        // address_of_names:         [ 0x00000044 | 0x00000055 ]
        //
        // The function at RVA 0x00000011 (index 0) has ordinal 5 (base+index).
        // The index can be found at position 0 in the address_of_name_ordinals
        // array. Using 0 to index into the address_of_names array gives us an
        // RVA (0x00000044) where the function's name is located.
        //
        // The function at RVA 0x00000022 (index 1) has ordinal 6 (base+index).
        // The index can be found at position 2 in the address_of_name_ordinals
        // array. 2 is out of bounds for address_of_names, so this function is
        // exported only by ordinal, not by name.
        //
        // The function at RVA 0x00000033 (index 2) has ordinal 7 (base+index).
        // The index can be found in position 1 in the address_of_name_ordinals.
        // array. Using 1 to index into the address_of_names array gives us an
        // RVA (0x00000055) which we can follow to get the name.
        //
        // If the RVA from the address_of_functions is within the export
        // directory it is a forwarder RVA and points to a NULL terminated
        // ASCII string.
        let mut func_rvas = iterator(
            self.data_at_rva(exports.address_of_functions).unwrap_or_default(),
            le_u32::<&[u8], Error>,
        );

        // Create a vector with one item per exported function. Items in the
        // array initially have function RVA and ordinal only.
        let mut exported_funcs: Vec<_> = func_rvas
            .take(num_exports)
            .enumerate()
            .filter_map(|(i, rva)| {
                Some(ExportedFunc {
                    rva,
                    ordinal: exports.base.checked_add(i as u32)?,
                    ..Default::default()
                })
            })
            .collect();

        let names = self
            .parse_at_rva(exports.address_of_names, count(le_u32, num_names))
            .unwrap_or_default();

        let name_ordinals = self
            .data_at_rva(exports.address_of_name_ordinals)
            .unwrap_or_default();

        // Set the name field for each exported function, if they are exported
        // by name.
        for f in exported_funcs.iter_mut() {
            // Find the index of the ordinal.
            if let Some((idx, _)) =
                iterator(name_ordinals, le_u16::<&[u8], Error>)
                    .take(num_names)
                    .find_position(|ordinal| {
                        *ordinal as u32 == f.ordinal - exports.base
                    })
            {
                if let Some(name_rva) = names.get(idx) {
                    f.name = self.str_at_rva(*name_rva);
                }
            }

            // If the function's RVA is within the exports section (as given
            // by the RVA and size fields in the directory entry), this is a
            // forwarded function. In such cases the function's RVA is not
            // really pointing to the function, but to a ASCII string that
            // contains the DLL and function to which this export is forwarded.
            if exports_section.contains(&f.rva) {
                f.forward_name = self.str_at_rva(f.rva);
            } else {
                f.offset = self.rva_to_offset(f.rva);
            }
        }

        Some(ExportInfo {
            dll_name: self.dll_name_at_rva(exports.name),
            timestamp: exports.timestamp,
            functions: exported_funcs,
        })
    }

    fn parse_exports_dir_entry(
        input: &[u8],
    ) -> IResult<&[u8], ExportsDirEntry> {
        map(
            tuple((
                le_u32, // characteristics
                le_u32, // timestamp
                le_u16, // major_version
                le_u16, // minor_version
                le_u32, // name
                le_u32, // base
                le_u32, // number_of_functions
                le_u32, // number_of_names
                le_u32, // address_of_functions
                le_u32, // address_of_names
                le_u32, // address_of_name_ordinals
            )),
            |(
                characteristics,
                timestamp,
                major_version,
                minor_version,
                name,
                base,
                number_of_functions,
                number_of_names,
                address_of_functions,
                address_of_names,
                address_of_name_ordinals,
            )| {
                ExportsDirEntry {
                    characteristics,
                    timestamp,
                    major_version,
                    minor_version,
                    name,
                    base,
                    number_of_functions,
                    number_of_names,
                    address_of_functions,
                    address_of_names,
                    address_of_name_ordinals,
                }
            },
        )(input)
    }

    fn parse_at_rva<T, P>(&self, rva: u32, mut parser: P) -> Option<T>
    where
        P: FnMut(&'a [u8]) -> IResult<&'a [u8], T>,
    {
        let data = self.data_at_rva(rva)?;
        parser(data).map(|(_, result)| result).ok()
    }

    fn str_at_rva(&self, rva: u32) -> Option<&'a str> {
        let dll_name = self.parse_at_rva(rva, take_till(|c| c == 0))?;
        from_utf8(dll_name).ok()
    }

    fn dll_name_at_rva(&self, rva: u32) -> Option<&'a str> {
        // TODO: this enforces the DLL name to be valid UTF-8. Is this too
        // restrictive? YARA is using a more relaxed approach and accepts
        // every byte except the ones listed below. YARA imposes a length
        // limit of 256 bytes, though.
        let dll_name = self.str_at_rva(rva)?;

        for c in dll_name.chars() {
            if c.is_ascii_control() {
                return None;
            }
            if matches!(c, ' ' | '"' | '*' | '<' | '>' | '?' | '|') {
                return None;
            }
        }

        Some(dll_name)
    }
}

#[rustfmt::skip]
impl From<PE<'_>> for protos::pe::PE {
    fn from(pe: PE) -> Self {
        let mut result = protos::pe::PE::new();

        result.set_is_pe(true);
        result.machine = Some(EnumOrUnknown::<protos::pe::Machine>::from_i32(pe
            .pe_hdr
            .machine
            .into()));

        result.set_timestamp(pe.pe_hdr.timestamp);
        result.set_characteristics(pe.pe_hdr.characteristics.into());
        result.set_number_of_sections(pe.pe_hdr.number_of_sections.into());
        result.set_pointer_to_symbol_table(pe.pe_hdr.symbol_table_offset);
        result.set_number_of_symbols(pe.pe_hdr.number_of_symbols);
        result.set_size_of_optional_header(pe.pe_hdr.size_of_optional_header.into());

        result.opthdr_magic = Some(EnumOrUnknown::<protos::pe::OptHdrMagic>::from_i32(pe
            .optional_hdr
            .magic.into()));

        result.subsystem = Some(EnumOrUnknown::<protos::pe::Subsystem>::from_i32(pe
            .optional_hdr
            .subsystem.into()));

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
        result.pdb_path = pe.get_pdb_path().map(|path| path.to_vec());
        result.set_number_of_rva_and_sizes(pe.optional_hdr.number_of_rva_and_sizes);
        result.set_image_base(pe.optional_hdr.image_base);
        result.set_size_of_image(pe.optional_hdr.size_of_image);
        result.set_size_of_headers(pe.optional_hdr.size_of_headers);
        result.set_size_of_initialized_data(pe.optional_hdr.size_of_initialized_data);
        result.set_size_of_uninitialized_data(pe.optional_hdr.size_of_uninitialized_data);

        result.linker_version = MessageField::some(protos::pe::Version {
            major: Some(pe.optional_hdr.major_linker_version.into()),
            minor: Some(pe.optional_hdr.minor_linker_version.into()),
            ..Default::default()
        });

        result.os_version = MessageField::some(protos::pe::Version {
            major: Some(pe.optional_hdr.major_os_version.into()),
            minor: Some(pe.optional_hdr.minor_os_version.into()),
            ..Default::default()
        });

        result.image_version = MessageField::some(protos::pe::Version {
            major: Some(pe.optional_hdr.major_image_version.into()),
            minor: Some(pe.optional_hdr.minor_image_version.into()),
            ..Default::default()
        });

        result.subsystem_version = MessageField::some(protos::pe::Version {
            major: Some(pe.optional_hdr.major_subsystem_version.into()),
            minor: Some(pe.optional_hdr.minor_subsystem_version.into()),
            ..Default::default()
        });

        result
            .data_directories
            .extend(pe.get_dir_entries().iter().map(protos::pe::DirEntry::from));

        result
            .sections
            .extend(pe.get_sections().iter().map(protos::pe::Section::from));

        result
            .resources
            .extend(pe.get_resources().iter().map(protos::pe::Resource::from));

        result
            .signatures
            .extend(pe.get_signatures().iter().map(protos::pe::Signature::from));

        result.set_is_signed(
            result.signatures.iter().any(|signature| signature.verified.is_some_and(|v| v)));

        let mut num_imported_funcs = 0;
        let mut num_delayed_imported_funcs = 0;

        if let Some(imports) = pe.get_imports() {
            for (dll_name, functions) in imports {
                let mut import = protos::pe::Import::new();
                import.library_name = Some(dll_name.to_owned());
                import.functions = functions.iter().map(protos::pe::Function::from).collect();
                import.set_number_of_functions(functions.len().try_into().unwrap());
                num_imported_funcs += import.functions.len();
                result.import_details.push(import);
            }
        }

        if let Some(delayed_imports) = pe.get_delayed_imports() {
            for (dll_name, functions) in delayed_imports {
                let mut import = protos::pe::Import::new();
                import.library_name = Some(dll_name.to_owned());
                import.functions = functions.iter().map(protos::pe::Function::from).collect();
                import.set_number_of_functions(functions.len().try_into().unwrap());
                num_delayed_imported_funcs += import.functions.len();
                result.delayed_import_details.push(import);
            }
        }

        result.set_number_of_imported_functions(num_imported_funcs as u64);
        result.set_number_of_delayed_imported_functions(num_delayed_imported_funcs as u64);

        if let Some(exports) = pe.get_exports() {
            result.dll_name = exports.dll_name.map(|name| name.to_owned());
            result.export_timestamp = Some(exports.timestamp);
            result.export_details.extend(exports.functions.iter().map(protos::pe::Export::from));
        }

        for (key, value) in pe.get_version_info() {
            let mut kv = protos::pe::KeyValue::new();
            kv.key = Some(key.to_owned());
            kv.value = Some(value.to_owned());
            result.version_info_list.push(kv);
            result.version_info.insert(key.to_owned(), value.to_owned());
        }

        if let Some(rich_header) = pe.get_rich_header() {
            result.rich_signature = MessageField::some(protos::pe::RichSignature {
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
                        let mut entry = protos::pe::RichTool::new();
                        entry.toolid = Some((*toolid).into());
                        entry.version = Some((*version).into());
                        entry.times = Some(*times);
                        entry
                    })
                    .collect(),
                ..Default::default()
            });
        }

        if let Some(res) = pe.get_resource_dir() {
            result.resource_timestamp = Some(res.timestamp as u64);
            result.resource_version = MessageField::some(protos::pe::Version {
                major: Some(res.major_version.into()),
                minor: Some(res.minor_version.into()),
                ..Default::default()
            });
        };


        result.set_number_of_resources(
            result.resources.len().try_into().unwrap());

        result.set_number_of_sections(
            result.sections.len().try_into().unwrap());

        result.set_number_of_version_infos(
            result.version_info_list.len().try_into().unwrap());

        result.set_number_of_imports(
            result.import_details.len().try_into().unwrap());

        result.set_number_of_delayed_imports(
            result.delayed_import_details.len().try_into().unwrap());

        result.set_number_of_exports(
            result.export_details.len().try_into().unwrap());

        result.set_number_of_signatures(
            result.signatures.len().try_into().unwrap());

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
                (Some(offset), Some(size)) if size > 0 => protos::pe::Overlay {
                    offset: Some(offset),
                    size: Some(size),
                    ..Default::default()
                },
                _ => protos::pe::Overlay {
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
    image_base: u64,
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

impl From<&Section<'_>> for protos::pe::Section {
    fn from(value: &Section) -> Self {
        let mut sec = protos::pe::Section::new();
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

impl rva2off::Section for Section<'_> {
    fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    fn virtual_size(&self) -> u32 {
        self.virtual_size
    }

    fn raw_data_offset(&self) -> u32 {
        self.raw_data_offset
    }

    fn raw_data_size(&self) -> u32 {
        self.raw_data_size
    }
}

pub struct DirEntry {
    pub addr: u32,
    pub size: u32,
}

impl From<&DirEntry> for protos::pe::DirEntry {
    fn from(value: &DirEntry) -> Self {
        let mut entry = protos::pe::DirEntry::new();
        entry.virtual_address = Some(value.addr);
        entry.size = Some(value.size);
        entry
    }
}

#[derive(Debug, Default)]
pub struct ResourceDir {
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    number_of_entries: usize,
}

#[derive(Debug)]
pub struct ResourceDirEntry<'a> {
    /// True if this entry corresponds to a resource subdirectory.
    is_subdir: bool,
    /// Resource ID or name.
    id: ResourceId<'a>,
    /// Offset relative to the resources section where the data is found.
    offset: usize,
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
    /// True if the values of the rest of the fields are virtual addresses
    /// instead of relative virtual addresses (RVAs).
    va_values: bool,
    name: u32,
    import_name_table: u32,
    import_address_table: u32,
}

#[derive(Debug, Default)]
pub struct ImportedFunc {
    name: Option<String>,
    ordinal: Option<u16>,
    rva: u32,
}

impl From<&ImportedFunc> for protos::pe::Function {
    fn from(value: &ImportedFunc) -> Self {
        let mut func = protos::pe::Function::new();
        func.rva = Some(value.rva);
        func.ordinal = value.ordinal.map(|ordinal| ordinal.into());
        func.name.clone_from(&value.name);
        func
    }
}

pub struct ExportInfo<'a> {
    dll_name: Option<&'a str>,
    timestamp: u32,
    functions: Vec<ExportedFunc<'a>>,
}

#[derive(Default)]
pub struct ExportedFunc<'a> {
    rva: u32,
    offset: Option<u32>,
    ordinal: u32,
    name: Option<&'a str>,
    forward_name: Option<&'a str>,
}

impl From<&ExportedFunc<'_>> for protos::pe::Export {
    fn from(value: &ExportedFunc<'_>) -> Self {
        let mut exp = protos::pe::Export::new();
        exp.name = value.name.map(|name| name.to_owned());
        exp.ordinal = Some(value.ordinal);
        exp.rva = Some(value.rva);
        exp.offset = value.offset;
        exp.forward_name = value.forward_name.map(|name| name.to_owned());
        exp
    }
}

#[allow(dead_code)]
pub struct ExportsDirEntry {
    characteristics: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
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

impl From<&Resource<'_>> for protos::pe::Resource {
    fn from(value: &Resource) -> Self {
        let mut resource = protos::pe::Resource::new();
        resource.rva = Some(value.rva);
        resource.length = Some(value.length);
        resource.offset = value.offset;

        match value.type_id {
            ResourceId::Id(id) => {
                resource.type_ = id
                    .try_into()
                    .ok()
                    .map(EnumOrUnknown::<protos::pe::ResourceType>::from_i32);
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

#[allow(dead_code)]
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

/// Parser that reads a UTF-16LE string.
///
/// If the string is null-terminated, the parser will consume the input, including
/// the null terminator, and return the rest as the remainder. If the string is
/// not null terminated, all the input is expected to contain a UTF-16LE string.
/// The resulting string is a UTF-8 string.
fn utf16_le_string() -> impl FnMut(&[u8]) -> IResult<&[u8], String> {
    move |input: &[u8]| {
        // Read UTF-16 chars until a null terminator is found, or the end
        // of the input is reached.
        let (mut remainder, string) =
            many0(verify(le_u16, |c| *c != 0_u16))(input)?;

        // Consume the null-terminator, if any.
        if !remainder.is_empty() {
            (remainder, _) = take(2_usize)(remainder)?;
        }

        let s = String::from_utf16_lossy(string.as_slice());

        Ok((remainder, s))
    }
}

/// Convert ordinal number to function name.
///
/// For some well-known DLLs the returned name is the one that that corresponds
/// to the given ordinal. For the remaining DLLs the returned name has the form
/// "ordN" where N is the ordinal (e.g: "ord1", "ord23").
fn ord_to_name(dll_name: &str, ordinal: u16) -> Option<String> {
    let func_name = match dll_name.to_ascii_lowercase().as_str() {
        "ws2_32.dll" | "wsock32.dll" => wsock32_ord_to_name(ordinal),
        "oleaut32.dll" => oleaut32_ord_to_name(ordinal),
        _ => None,
    };

    func_name.map(|n| n.to_owned()).or_else(|| Some(format!("ord{}", ordinal)))
}

/// Convert ordinal number to function name for oleaut32.dll.
fn oleaut32_ord_to_name(ordinal: u16) -> Option<&'static str> {
    static OLEAUT32_ORD_TO_NAME: OnceLock<HashMap<u16, &'static str>> =
        OnceLock::new();

    let m = OLEAUT32_ORD_TO_NAME.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(2, "SysAllocString");
        m.insert(3, "SysReAllocString");
        m.insert(4, "SysAllocStringLen");
        m.insert(5, "SysReAllocStringLen");
        m.insert(6, "SysFreeString");
        m.insert(7, "SysStringLen");
        m.insert(8, "VariantInit");
        m.insert(9, "VariantClear");
        m.insert(10, "VariantCopy");
        m.insert(11, "VariantCopyInd");
        m.insert(12, "VariantChangeType");
        m.insert(13, "VariantTimeToDosDateTime");
        m.insert(14, "DosDateTimeToVariantTime");
        m.insert(15, "SafeArrayCreate");
        m.insert(16, "SafeArrayDestroy");
        m.insert(17, "SafeArrayGetDim");
        m.insert(18, "SafeArrayGetElemsize");
        m.insert(19, "SafeArrayGetUBound");
        m.insert(20, "SafeArrayGetLBound");
        m.insert(21, "SafeArrayLock");
        m.insert(22, "SafeArrayUnlock");
        m.insert(23, "SafeArrayAccessData");
        m.insert(24, "SafeArrayUnaccessData");
        m.insert(25, "SafeArrayGetElement");
        m.insert(26, "SafeArrayPutElement");
        m.insert(27, "SafeArrayCopy");
        m.insert(28, "DispGetParam");
        m.insert(29, "DispGetIDsOfNames");
        m.insert(30, "DispInvoke");
        m.insert(31, "CreateDispTypeInfo");
        m.insert(32, "CreateStdDispatch");
        m.insert(33, "RegisterActiveObject");
        m.insert(34, "RevokeActiveObject");
        m.insert(35, "GetActiveObject");
        m.insert(36, "SafeArrayAllocDescriptor");
        m.insert(37, "SafeArrayAllocData");
        m.insert(38, "SafeArrayDestroyDescriptor");
        m.insert(39, "SafeArrayDestroyData");
        m.insert(40, "SafeArrayRedim");
        m.insert(41, "SafeArrayAllocDescriptorEx");
        m.insert(42, "SafeArrayCreateEx");
        m.insert(43, "SafeArrayCreateVectorEx");
        m.insert(44, "SafeArraySetRecordInfo");
        m.insert(45, "SafeArrayGetRecordInfo");
        m.insert(46, "VarParseNumFromStr");
        m.insert(47, "VarNumFromParseNum");
        m.insert(48, "VarI2FromUI1");
        m.insert(49, "VarI2FromI4");
        m.insert(50, "VarI2FromR4");
        m.insert(51, "VarI2FromR8");
        m.insert(52, "VarI2FromCy");
        m.insert(53, "VarI2FromDate");
        m.insert(54, "VarI2FromStr");
        m.insert(55, "VarI2FromDisp");
        m.insert(56, "VarI2FromBool");
        m.insert(57, "SafeArraySetIID");
        m.insert(58, "VarI4FromUI1");
        m.insert(59, "VarI4FromI2");
        m.insert(60, "VarI4FromR4");
        m.insert(61, "VarI4FromR8");
        m.insert(62, "VarI4FromCy");
        m.insert(63, "VarI4FromDate");
        m.insert(64, "VarI4FromStr");
        m.insert(65, "VarI4FromDisp");
        m.insert(66, "VarI4FromBool");
        m.insert(67, "SafeArrayGetIID");
        m.insert(68, "VarR4FromUI1");
        m.insert(69, "VarR4FromI2");
        m.insert(70, "VarR4FromI4");
        m.insert(71, "VarR4FromR8");
        m.insert(72, "VarR4FromCy");
        m.insert(73, "VarR4FromDate");
        m.insert(74, "VarR4FromStr");
        m.insert(75, "VarR4FromDisp");
        m.insert(76, "VarR4FromBool");
        m.insert(77, "SafeArrayGetVartype");
        m.insert(78, "VarR8FromUI1");
        m.insert(79, "VarR8FromI2");
        m.insert(80, "VarR8FromI4");
        m.insert(81, "VarR8FromR4");
        m.insert(82, "VarR8FromCy");
        m.insert(83, "VarR8FromDate");
        m.insert(84, "VarR8FromStr");
        m.insert(85, "VarR8FromDisp");
        m.insert(86, "VarR8FromBool");
        m.insert(87, "VarFormat");
        m.insert(88, "VarDateFromUI1");
        m.insert(89, "VarDateFromI2");
        m.insert(90, "VarDateFromI4");
        m.insert(91, "VarDateFromR4");
        m.insert(92, "VarDateFromR8");
        m.insert(93, "VarDateFromCy");
        m.insert(94, "VarDateFromStr");
        m.insert(95, "VarDateFromDisp");
        m.insert(96, "VarDateFromBool");
        m.insert(97, "VarFormatDateTime");
        m.insert(98, "VarCyFromUI1");
        m.insert(99, "VarCyFromI2");
        m.insert(100, "VarCyFromI4");
        m.insert(101, "VarCyFromR4");
        m.insert(102, "VarCyFromR8");
        m.insert(103, "VarCyFromDate");
        m.insert(104, "VarCyFromStr");
        m.insert(105, "VarCyFromDisp");
        m.insert(106, "VarCyFromBool");
        m.insert(107, "VarFormatNumber");
        m.insert(108, "VarBstrFromUI1");
        m.insert(109, "VarBstrFromI2");
        m.insert(110, "VarBstrFromI4");
        m.insert(111, "VarBstrFromR4");
        m.insert(112, "VarBstrFromR8");
        m.insert(113, "VarBstrFromCy");
        m.insert(114, "VarBstrFromDate");
        m.insert(115, "VarBstrFromDisp");
        m.insert(116, "VarBstrFromBool");
        m.insert(117, "VarFormatPercent");
        m.insert(118, "VarBoolFromUI1");
        m.insert(119, "VarBoolFromI2");
        m.insert(120, "VarBoolFromI4");
        m.insert(121, "VarBoolFromR4");
        m.insert(122, "VarBoolFromR8");
        m.insert(123, "VarBoolFromDate");
        m.insert(124, "VarBoolFromCy");
        m.insert(125, "VarBoolFromStr");
        m.insert(126, "VarBoolFromDisp");
        m.insert(127, "VarFormatCurrency");
        m.insert(128, "VarWeekdayName");
        m.insert(129, "VarMonthName");
        m.insert(130, "VarUI1FromI2");
        m.insert(131, "VarUI1FromI4");
        m.insert(132, "VarUI1FromR4");
        m.insert(133, "VarUI1FromR8");
        m.insert(134, "VarUI1FromCy");
        m.insert(135, "VarUI1FromDate");
        m.insert(136, "VarUI1FromStr");
        m.insert(137, "VarUI1FromDisp");
        m.insert(138, "VarUI1FromBool");
        m.insert(139, "VarFormatFromTokens");
        m.insert(140, "VarTokenizeFormatString");
        m.insert(141, "VarAdd");
        m.insert(142, "VarAnd");
        m.insert(143, "VarDiv");
        m.insert(144, "DllCanUnloadNow");
        m.insert(145, "DllGetClassObject");
        m.insert(146, "DispCallFunc");
        m.insert(147, "VariantChangeTypeEx");
        m.insert(148, "SafeArrayPtrOfIndex");
        m.insert(149, "SysStringByteLen");
        m.insert(150, "SysAllocStringByteLen");
        m.insert(151, "DllRegisterServer");
        m.insert(152, "VarEqv");
        m.insert(153, "VarIdiv");
        m.insert(154, "VarImp");
        m.insert(155, "VarMod");
        m.insert(156, "VarMul");
        m.insert(157, "VarOr");
        m.insert(158, "VarPow");
        m.insert(159, "VarSub");
        m.insert(160, "CreateTypeLib");
        m.insert(161, "LoadTypeLib");
        m.insert(162, "LoadRegTypeLib");
        m.insert(163, "RegisterTypeLib");
        m.insert(164, "QueryPathOfRegTypeLib");
        m.insert(165, "LHashValOfNameSys");
        m.insert(166, "LHashValOfNameSysA");
        m.insert(167, "VarXor");
        m.insert(168, "VarAbs");
        m.insert(169, "VarFix");
        m.insert(170, "OaBuildVersion");
        m.insert(171, "ClearCustData");
        m.insert(172, "VarInt");
        m.insert(173, "VarNeg");
        m.insert(174, "VarNot");
        m.insert(175, "VarRound");
        m.insert(176, "VarCmp");
        m.insert(177, "VarDecAdd");
        m.insert(178, "VarDecDiv");
        m.insert(179, "VarDecMul");
        m.insert(180, "CreateTypeLib2");
        m.insert(181, "VarDecSub");
        m.insert(182, "VarDecAbs");
        m.insert(183, "LoadTypeLibEx");
        m.insert(184, "SystemTimeToVariantTime");
        m.insert(185, "VariantTimeToSystemTime");
        m.insert(186, "UnRegisterTypeLib");
        m.insert(187, "VarDecFix");
        m.insert(188, "VarDecInt");
        m.insert(189, "VarDecNeg");
        m.insert(190, "VarDecFromUI1");
        m.insert(191, "VarDecFromI2");
        m.insert(192, "VarDecFromI4");
        m.insert(193, "VarDecFromR4");
        m.insert(194, "VarDecFromR8");
        m.insert(195, "VarDecFromDate");
        m.insert(196, "VarDecFromCy");
        m.insert(197, "VarDecFromStr");
        m.insert(198, "VarDecFromDisp");
        m.insert(199, "VarDecFromBool");
        m.insert(200, "GetErrorInfo");
        m.insert(201, "SetErrorInfo");
        m.insert(202, "CreateErrorInfo");
        m.insert(203, "VarDecRound");
        m.insert(204, "VarDecCmp");
        m.insert(205, "VarI2FromI1");
        m.insert(206, "VarI2FromUI2");
        m.insert(207, "VarI2FromUI4");
        m.insert(208, "VarI2FromDec");
        m.insert(209, "VarI4FromI1");
        m.insert(210, "VarI4FromUI2");
        m.insert(211, "VarI4FromUI4");
        m.insert(212, "VarI4FromDec");
        m.insert(213, "VarR4FromI1");
        m.insert(214, "VarR4FromUI2");
        m.insert(215, "VarR4FromUI4");
        m.insert(216, "VarR4FromDec");
        m.insert(217, "VarR8FromI1");
        m.insert(218, "VarR8FromUI2");
        m.insert(219, "VarR8FromUI4");
        m.insert(220, "VarR8FromDec");
        m.insert(221, "VarDateFromI1");
        m.insert(222, "VarDateFromUI2");
        m.insert(223, "VarDateFromUI4");
        m.insert(224, "VarDateFromDec");
        m.insert(225, "VarCyFromI1");
        m.insert(226, "VarCyFromUI2");
        m.insert(227, "VarCyFromUI4");
        m.insert(228, "VarCyFromDec");
        m.insert(229, "VarBstrFromI1");
        m.insert(230, "VarBstrFromUI2");
        m.insert(231, "VarBstrFromUI4");
        m.insert(232, "VarBstrFromDec");
        m.insert(233, "VarBoolFromI1");
        m.insert(234, "VarBoolFromUI2");
        m.insert(235, "VarBoolFromUI4");
        m.insert(236, "VarBoolFromDec");
        m.insert(237, "VarUI1FromI1");
        m.insert(238, "VarUI1FromUI2");
        m.insert(239, "VarUI1FromUI4");
        m.insert(240, "VarUI1FromDec");
        m.insert(241, "VarDecFromI1");
        m.insert(242, "VarDecFromUI2");
        m.insert(243, "VarDecFromUI4");
        m.insert(244, "VarI1FromUI1");
        m.insert(245, "VarI1FromI2");
        m.insert(246, "VarI1FromI4");
        m.insert(247, "VarI1FromR4");
        m.insert(248, "VarI1FromR8");
        m.insert(249, "VarI1FromDate");
        m.insert(250, "VarI1FromCy");
        m.insert(251, "VarI1FromStr");
        m.insert(252, "VarI1FromDisp");
        m.insert(253, "VarI1FromBool");
        m.insert(254, "VarI1FromUI2");
        m.insert(255, "VarI1FromUI4");
        m.insert(256, "VarI1FromDec");
        m.insert(257, "VarUI2FromUI1");
        m.insert(258, "VarUI2FromI2");
        m.insert(259, "VarUI2FromI4");
        m.insert(260, "VarUI2FromR4");
        m.insert(261, "VarUI2FromR8");
        m.insert(262, "VarUI2FromDate");
        m.insert(263, "VarUI2FromCy");
        m.insert(264, "VarUI2FromStr");
        m.insert(265, "VarUI2FromDisp");
        m.insert(266, "VarUI2FromBool");
        m.insert(267, "VarUI2FromI1");
        m.insert(268, "VarUI2FromUI4");
        m.insert(269, "VarUI2FromDec");
        m.insert(270, "VarUI4FromUI1");
        m.insert(271, "VarUI4FromI2");
        m.insert(272, "VarUI4FromI4");
        m.insert(273, "VarUI4FromR4");
        m.insert(274, "VarUI4FromR8");
        m.insert(275, "VarUI4FromDate");
        m.insert(276, "VarUI4FromCy");
        m.insert(277, "VarUI4FromStr");
        m.insert(278, "VarUI4FromDisp");
        m.insert(279, "VarUI4FromBool");
        m.insert(280, "VarUI4FromI1");
        m.insert(281, "VarUI4FromUI2");
        m.insert(282, "VarUI4FromDec");
        m.insert(283, "BSTR_UserSize");
        m.insert(284, "BSTR_UserMarshal");
        m.insert(285, "BSTR_UserUnmarshal");
        m.insert(286, "BSTR_UserFree");
        m.insert(287, "VARIANT_UserSize");
        m.insert(288, "VARIANT_UserMarshal");
        m.insert(289, "VARIANT_UserUnmarshal");
        m.insert(290, "VARIANT_UserFree");
        m.insert(291, "LPSAFEARRAY_UserSize");
        m.insert(292, "LPSAFEARRAY_UserMarshal");
        m.insert(293, "LPSAFEARRAY_UserUnmarshal");
        m.insert(294, "LPSAFEARRAY_UserFree");
        m.insert(295, "LPSAFEARRAY_Size");
        m.insert(296, "LPSAFEARRAY_Marshal");
        m.insert(297, "LPSAFEARRAY_Unmarshal");
        m.insert(298, "VarDecCmpR8");
        m.insert(299, "VarCyAdd");
        m.insert(300, "DllUnregisterServer");
        m.insert(301, "OACreateTypeLib2");
        m.insert(303, "VarCyMul");
        m.insert(304, "VarCyMulI4");
        m.insert(305, "VarCySub");
        m.insert(306, "VarCyAbs");
        m.insert(307, "VarCyFix");
        m.insert(308, "VarCyInt");
        m.insert(309, "VarCyNeg");
        m.insert(310, "VarCyRound");
        m.insert(311, "VarCyCmp");
        m.insert(312, "VarCyCmpR8");
        m.insert(313, "VarBstrCat");
        m.insert(314, "VarBstrCmp");
        m.insert(315, "VarR8Pow");
        m.insert(316, "VarR4CmpR8");
        m.insert(317, "VarR8Round");
        m.insert(318, "VarCat");
        m.insert(319, "VarDateFromUdateEx");
        m.insert(322, "GetRecordInfoFromGuids");
        m.insert(323, "GetRecordInfoFromTypeInfo");
        m.insert(325, "SetVarConversionLocaleSetting");
        m.insert(326, "GetVarConversionLocaleSetting");
        m.insert(327, "SetOaNoCache");
        m.insert(329, "VarCyMulI8");
        m.insert(330, "VarDateFromUdate");
        m.insert(331, "VarUdateFromDate");
        m.insert(332, "GetAltMonthNames");
        m.insert(333, "VarI8FromUI1");
        m.insert(334, "VarI8FromI2");
        m.insert(335, "VarI8FromR4");
        m.insert(336, "VarI8FromR8");
        m.insert(337, "VarI8FromCy");
        m.insert(338, "VarI8FromDate");
        m.insert(339, "VarI8FromStr");
        m.insert(340, "VarI8FromDisp");
        m.insert(341, "VarI8FromBool");
        m.insert(342, "VarI8FromI1");
        m.insert(343, "VarI8FromUI2");
        m.insert(344, "VarI8FromUI4");
        m.insert(345, "VarI8FromDec");
        m.insert(346, "VarI2FromI8");
        m.insert(347, "VarI2FromUI8");
        m.insert(348, "VarI4FromI8");
        m.insert(349, "VarI4FromUI8");
        m.insert(360, "VarR4FromI8");
        m.insert(361, "VarR4FromUI8");
        m.insert(362, "VarR8FromI8");
        m.insert(363, "VarR8FromUI8");
        m.insert(364, "VarDateFromI8");
        m.insert(365, "VarDateFromUI8");
        m.insert(366, "VarCyFromI8");
        m.insert(367, "VarCyFromUI8");
        m.insert(368, "VarBstrFromI8");
        m.insert(369, "VarBstrFromUI8");
        m.insert(370, "VarBoolFromI8");
        m.insert(371, "VarBoolFromUI8");
        m.insert(372, "VarUI1FromI8");
        m.insert(373, "VarUI1FromUI8");
        m.insert(374, "VarDecFromI8");
        m.insert(375, "VarDecFromUI8");
        m.insert(376, "VarI1FromI8");
        m.insert(377, "VarI1FromUI8");
        m.insert(378, "VarUI2FromI8");
        m.insert(379, "VarUI2FromUI8");
        m.insert(401, "OleLoadPictureEx");
        m.insert(402, "OleLoadPictureFileEx");
        m.insert(411, "SafeArrayCreateVector");
        m.insert(412, "SafeArrayCopyData");
        m.insert(413, "VectorFromBstr");
        m.insert(414, "BstrFromVector");
        m.insert(415, "OleIconToCursor");
        m.insert(416, "OleCreatePropertyFrameIndirect");
        m.insert(417, "OleCreatePropertyFrame");
        m.insert(418, "OleLoadPicture");
        m.insert(419, "OleCreatePictureIndirect");
        m.insert(420, "OleCreateFontIndirect");
        m.insert(421, "OleTranslateColor");
        m.insert(422, "OleLoadPictureFile");
        m.insert(423, "OleSavePictureFile");
        m.insert(424, "OleLoadPicturePath");
        m.insert(425, "VarUI4FromI8");
        m.insert(426, "VarUI4FromUI8");
        m.insert(427, "VarI8FromUI8");
        m.insert(428, "VarUI8FromI8");
        m.insert(429, "VarUI8FromUI1");
        m.insert(430, "VarUI8FromI2");
        m.insert(431, "VarUI8FromR4");
        m.insert(432, "VarUI8FromR8");
        m.insert(433, "VarUI8FromCy");
        m.insert(434, "VarUI8FromDate");
        m.insert(435, "VarUI8FromStr");
        m.insert(436, "VarUI8FromDisp");
        m.insert(437, "VarUI8FromBool");
        m.insert(438, "VarUI8FromI1");
        m.insert(439, "VarUI8FromUI2");
        m.insert(440, "VarUI8FromUI4");
        m.insert(441, "VarUI8FromDec");
        m.insert(442, "RegisterTypeLibForUser");
        m.insert(443, "UnRegisterTypeLibForUser");
        m
    });

    m.get(&ordinal).copied()
}

/// Convert ordinal number to function name for wsock32.dll and ws2_32.dll.
fn wsock32_ord_to_name(ordinal: u16) -> Option<&'static str> {
    static WSOCK32_ORD_TO_NAME: OnceLock<HashMap<u16, &'static str>> =
        OnceLock::new();

    let m = WSOCK32_ORD_TO_NAME.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(1, "accept");
        m.insert(2, "bind");
        m.insert(3, "closesocket");
        m.insert(4, "connect");
        m.insert(5, "getpeername");
        m.insert(6, "getsockname");
        m.insert(7, "getsockopt");
        m.insert(8, "htonl");
        m.insert(9, "htons");
        m.insert(10, "ioctlsocket");
        m.insert(11, "inet_addr");
        m.insert(12, "inet_ntoa");
        m.insert(13, "listen");
        m.insert(14, "ntohl");
        m.insert(15, "ntohs");
        m.insert(16, "recv");
        m.insert(17, "recvfrom");
        m.insert(18, "select");
        m.insert(19, "send");
        m.insert(20, "sendto");
        m.insert(21, "setsockopt");
        m.insert(22, "shutdown");
        m.insert(23, "socket");
        m.insert(24, "GetAddrInfoW");
        m.insert(25, "GetNameInfoW");
        m.insert(26, "WSApSetPostRoutine");
        m.insert(27, "FreeAddrInfoW");
        m.insert(28, "WPUCompleteOverlappedRequest");
        m.insert(29, "WSAAccept");
        m.insert(30, "WSAAddressToStringA");
        m.insert(31, "WSAAddressToStringW");
        m.insert(32, "WSACloseEvent");
        m.insert(33, "WSAConnect");
        m.insert(34, "WSACreateEvent");
        m.insert(35, "WSADuplicateSocketA");
        m.insert(36, "WSADuplicateSocketW");
        m.insert(37, "WSAEnumNameSpaceProvidersA");
        m.insert(38, "WSAEnumNameSpaceProvidersW");
        m.insert(39, "WSAEnumNetworkEvents");
        m.insert(40, "WSAEnumProtocolsA");
        m.insert(41, "WSAEnumProtocolsW");
        m.insert(42, "WSAEventSelect");
        m.insert(43, "WSAGetOverlappedResult");
        m.insert(44, "WSAGetQOSByName");
        m.insert(45, "WSAGetServiceClassInfoA");
        m.insert(46, "WSAGetServiceClassInfoW");
        m.insert(47, "WSAGetServiceClassNameByClassIdA");
        m.insert(48, "WSAGetServiceClassNameByClassIdW");
        m.insert(49, "WSAHtonl");
        m.insert(50, "WSAHtons");
        m.insert(51, "gethostbyaddr");
        m.insert(52, "gethostbyname");
        m.insert(53, "getprotobyname");
        m.insert(54, "getprotobynumber");
        m.insert(55, "getservbyname");
        m.insert(56, "getservbyport");
        m.insert(57, "gethostname");
        m.insert(58, "WSAInstallServiceClassA");
        m.insert(59, "WSAInstallServiceClassW");
        m.insert(60, "WSAIoctl");
        m.insert(61, "WSAJoinLeaf");
        m.insert(62, "WSALookupServiceBeginA");
        m.insert(63, "WSALookupServiceBeginW");
        m.insert(64, "WSALookupServiceEnd");
        m.insert(65, "WSALookupServiceNextA");
        m.insert(66, "WSALookupServiceNextW");
        m.insert(67, "WSANSPIoctl");
        m.insert(68, "WSANtohl");
        m.insert(69, "WSANtohs");
        m.insert(70, "WSAProviderConfigChange");
        m.insert(71, "WSARecv");
        m.insert(72, "WSARecvDisconnect");
        m.insert(73, "WSARecvFrom");
        m.insert(74, "WSARemoveServiceClass");
        m.insert(75, "WSAResetEvent");
        m.insert(76, "WSASend");
        m.insert(77, "WSASendDisconnect");
        m.insert(78, "WSASendTo");
        m.insert(79, "WSASetEvent");
        m.insert(80, "WSASetServiceA");
        m.insert(81, "WSASetServiceW");
        m.insert(82, "WSASocketA");
        m.insert(83, "WSASocketW");
        m.insert(84, "WSAStringToAddressA");
        m.insert(85, "WSAStringToAddressW");
        m.insert(86, "WSAWaitForMultipleEvents");
        m.insert(87, "WSCDeinstallProvider");
        m.insert(88, "WSCEnableNSProvider");
        m.insert(89, "WSCEnumProtocols");
        m.insert(90, "WSCGetProviderPath");
        m.insert(91, "WSCInstallNameSpace");
        m.insert(92, "WSCInstallProvider");
        m.insert(93, "WSCUnInstallNameSpace");
        m.insert(94, "WSCUpdateProvider");
        m.insert(95, "WSCWriteNameSpaceOrder");
        m.insert(96, "WSCWriteProviderOrder");
        m.insert(97, "freeaddrinfo");
        m.insert(98, "getaddrinfo");
        m.insert(99, "getnameinfo");
        m.insert(101, "WSAAsyncSelect");
        m.insert(102, "WSAAsyncGetHostByAddr");
        m.insert(103, "WSAAsyncGetHostByName");
        m.insert(104, "WSAAsyncGetProtoByNumber");
        m.insert(105, "WSAAsyncGetProtoByName");
        m.insert(106, "WSAAsyncGetServByPort");
        m.insert(107, "WSAAsyncGetServByName");
        m.insert(108, "WSACancelAsyncRequest");
        m.insert(109, "WSASetBlockingHook");
        m.insert(110, "WSAUnhookBlockingHook");
        m.insert(111, "WSAGetLastError");
        m.insert(112, "WSASetLastError");
        m.insert(113, "WSACancelBlockingCall");
        m.insert(114, "WSAIsBlocking");
        m.insert(115, "WSAStartup");
        m.insert(116, "WSACleanup");
        m.insert(151, "__WSAFDIsSet");
        m.insert(500, "WEP");
        m
    });

    m.get(&ordinal).copied()
}
