use std::iter::zip;
use std::mem;

use bstr::{BStr, ByteSlice};
use memchr::memmem;
use nom::bytes::complete::take;
use nom::combinator::{cond, map, verify};
use nom::error::ErrorKind;
use nom::multi::count;
use nom::number::complete::{le_u16, le_u32, u8};
use nom::number::streaming::le_u64;
use nom::sequence::tuple;
use nom::{Err, IResult, Parser};
use protobuf::{EnumOrUnknown, MessageField};

use crate::modules::protos::pe;

/// A PE file parser.
pub struct PEParser {
    result: pe::PE,
}

impl PEParser {
    /// Creates a new parser for PE files.
    pub fn new() -> Self {
        Self { result: pe::PE::default() }
    }

    /// Parses an PE file and produces a [`pe::PE`] protobuf containing
    /// metadata extracted from the file.
    pub fn parse<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<pe::PE, Err<nom::error::Error<&'a [u8]>>> {
        // Parse the MZ header.
        let (_dos_stub, pe_hdr_offset) = self.parse_dos_header()(data)?;

        // The PE header starts at the offset indicated by `pe_hdr_offset`.
        // Everything between offset 0 and `pe_hdr_offset` is stored in the
        // dos_hdr slice, including the DOS header, the MS-DOS stub and the
        // rich signature.
        let (pe_hdr, dos_hdr) = take(pe_hdr_offset)(data)?;

        // Parse the PE file header (IMAGE_FILE_HEADER).
        let (optional_hdr, _) = self.parse_pe_header()(pe_hdr)?;

        // Parse the PE optional header (IMAGE_OPTIONAL_HEADER).
        let (directory, _) = self.parse_optional_header()(optional_hdr)?;

        // Parse the Rich signature located in between the DOS header and the
        // PE header.
        let _ = self.parse_rich_signature()(dos_hdr);

        // The number of directory entries is limited to 16.
        let num_dir_entries = usize::max(
            self.result.number_of_rva_and_sizes.unwrap() as usize,
            16,
        );

        // Parse the data directory.
        let (_, dir_entries) =
            count(self.parse_dir_entry(), num_dir_entries)(directory)?;

        for entry in dir_entries.iter() {
            self.result.data_directories.push(entry.into())
        }

        // Parse the section table. The section table is located right after
        // NT headers, which starts at pe_hdr and is composed of a the PE
        // signature, the file header, and a variable-length optional header.
        if let Some(section_table) = pe_hdr.get(
            Self::SIZE_OF_PE_SIGNATURE
                + Self::SIZE_OF_FILE_HEADER
                + self.result.size_of_optional_header.unwrap() as usize..,
        ) {
            // The number of sections is capped to MAX_PE_SECTIONS.
            let num_sections = usize::min(
                self.result.number_of_sections.unwrap() as usize,
                Self::MAX_PE_SECTIONS,
            );

            let _ = count(self.parse_section(), num_sections)(section_table);
        }

        let overlay_offset = self.end_of_last_section();
        let overlay_size = overlay_offset.and_then(|overlay_offset| {
            (data.len() as u64).checked_sub(overlay_offset)
        });

        // For PE files that have overlaid data overlay.offset contains the offset
        // within the file where the overlay starts and overlay.size contains the
        // size. If the PE file doesn't have an overlay both fields are 0, if the
        // file is not a PE file (or is a malformed PE) both fields are undefined.
        self.result.overlay =
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

        Ok(mem::take(&mut self.result))
    }
}

impl PEParser {
    const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
    const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
    const MAX_PE_SECTIONS: usize = 96;
    const SIZE_OF_PE_SIGNATURE: usize = 4; // size of PE signature (PE\0\0).
    const SIZE_OF_FILE_HEADER: usize = 20; // size of IMAGE_FILE_HEADER
    const RICH: u32 = 0x68636952; // "Rich"
    const RICH_TAG: &'static [u8] = &[0x52_u8, 0x69, 0x63, 0x68];

    fn parse_dos_header(
        &self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], u32> + 'static {
        move |input: &[u8]| {
            let (
                remainder,
                (
                    _e_magic,    // DOS magic.
                    _e_cblp,     // Bytes on last page of file
                    _e_cp,       // Pages in file
                    _e_crlc,     // Relocations
                    _e_cparhdr,  // Size of header in paragraphs
                    _e_minalloc, // Minimum extra paragraphs needed
                    _e_maxalloc, // Maximum extra paragraphs needed
                    _e_ss,       // Initial (relative) SS value
                    _e_sp,       // Initial SP value
                    _e_csum,     // Checksum
                    _e_ip,       // Initial IP value
                    _e_cs,       // Initial (relative) CS value
                    _e_lfarlc,   // File address of relocation table
                    _e_ovno,     // Overlay number
                    _e_res,      // Reserved words
                    _e_oemid,    // OEM identifier (for e_oeminfo)
                    _e_oeminfo,  // OEM information; e_oemid specific
                    _e_res2,     // Reserved words
                    e_lfanew,    // File address of new exe header
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

            Ok((remainder, e_lfanew))
        }
    }

    fn parse_pe_header(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (
                optional_header,
                (
                    _magic,
                    machine,
                    number_of_sections,
                    timestamp,
                    ptr_sym_table,
                    number_of_symbols,
                    size_of_optional_header,
                    characteristics,
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

            self.result.is_pe = Some(true);
            self.result.machine = machine
                .try_into()
                .ok()
                .map(EnumOrUnknown::<pe::Machine>::from_i32);

            self.result.timestamp = Some(timestamp);
            self.result.characteristics = Some(characteristics.into());
            self.result.number_of_sections = Some(number_of_sections.into());
            self.result.pointer_to_symbol_table = Some(ptr_sym_table);
            self.result.number_of_symbols = Some(number_of_symbols);
            self.result.size_of_optional_header =
                Some(size_of_optional_header.into());

            Ok((optional_header, ()))
        }
    }

    fn parse_optional_header(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (
                remainder,
                (
                    magic,
                    major_linker_version,
                    minor_linker_version,
                    size_of_code,
                    size_of_initialized_data,
                    size_of_uninitialized_data,
                    entry_point,
                    base_of_code,
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

            let (
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

            let (
                remainder,
                (
                    section_alignment,
                    file_alignment,
                    major_os_version,
                    minor_os_version,
                    major_image_version,
                    minor_image_version,
                    major_subsystem_version,
                    minor_subsystem_version,
                    win32_version,
                    size_of_image,
                    size_of_headers,
                    checksum,
                    subsystem,
                    dll_characteristics,
                    size_of_stack_reserve,
                    size_of_stack_commit,
                    size_of_heap_reserve,
                    size_of_heap_commit,
                    loader_flags,
                    number_of_rva_and_sizes,
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

            self.result.size_of_code = Some(size_of_code);
            self.result.base_of_code = Some(base_of_code);
            self.result.base_of_data = base_of_data;
            self.result.entry_point_raw = Some(entry_point);
            self.result.section_alignment = Some(section_alignment);
            self.result.file_alignment = Some(file_alignment);
            // TODO
            //self.result.entry_point =
            self.result.loader_flags = Some(loader_flags);
            self.result.dll_characteristics = Some(dll_characteristics.into());
            self.result.checksum = Some(checksum);
            self.result.win32_version_value = Some(win32_version);
            self.result.size_of_stack_reserve = Some(size_of_stack_reserve);
            self.result.size_of_stack_commit = Some(size_of_stack_commit);
            self.result.size_of_heap_reserve = Some(size_of_heap_reserve);
            self.result.size_of_heap_commit = Some(size_of_heap_commit);

            self.result.number_of_rva_and_sizes =
                Some(number_of_rva_and_sizes);

            // TODO
            // number_of_version_infos
            // opthdr_magic

            self.result.image_base =
                image_base64.or(image_base32.map(|i| i as u64));

            self.result.size_of_image = Some(size_of_image);
            self.result.size_of_headers = Some(size_of_headers);

            self.result.size_of_initialized_data =
                Some(size_of_initialized_data);

            self.result.size_of_uninitialized_data =
                Some(size_of_uninitialized_data);

            self.result.linker_version = MessageField::some(pe::Version {
                major: Some(major_linker_version.into()),
                minor: Some(minor_linker_version.into()),
                special_fields: Default::default(),
            });

            self.result.os_version = MessageField::some(pe::Version {
                major: Some(major_os_version.into()),
                minor: Some(minor_os_version.into()),
                special_fields: Default::default(),
            });

            self.result.image_version = MessageField::some(pe::Version {
                major: Some(major_image_version.into()),
                minor: Some(minor_image_version.into()),
                special_fields: Default::default(),
            });

            self.result.subsystem_version = MessageField::some(pe::Version {
                major: Some(major_subsystem_version.into()),
                minor: Some(minor_subsystem_version.into()),
                special_fields: Default::default(),
            });

            self.result.subsystem = subsystem
                .try_into()
                .ok()
                .map(EnumOrUnknown::<pe::Subsystem>::from_i32);

            Ok((remainder, ()))
        }
    }

    fn parse_dir_entry(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], DirEntry> + '_ {
        move |input: &[u8]| {
            map(tuple((le_u32, le_u32)), |(addr, size)| DirEntry {
                addr,
                size,
            })(input)
        }
    }

    fn parse_section(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (
                remainder,
                (
                    name,
                    virtual_size,
                    virtual_address,
                    raw_data_size,
                    raw_data_offset,
                    pointer_to_relocations,
                    pointer_to_line_numbers,
                    number_of_relocations,
                    number_of_line_numbers,
                    characteristics,
                ),
            ) = tuple((
                take(8_usize), // name
                le_u32,        // virtual_size
                le_u32,        // virtual_address
                le_u32,        // raw_data_size
                le_u32,        // raw_data_offset
                le_u32,        // pointer_to_relocations
                le_u32,        // pointer_to_line_numbers
                le_u16,        // number_of_relocations
                le_u16,        // number_of_line_numbers
                le_u32,        // characteristics
            ))(input)?;

            // The PE specification states that:
            //
            // "Section name is an 8-byte, null-padded UTF-8 encoded string.
            // If the string is exactly 8 characters long, there is no
            // terminating null.".
            //
            // Here we remove the trailing nulls, if any, but don't assume that
            // the name is valid UTF-8 because some files have section names
            // containing zeroes or non-valid UTF-8. For example, file
            // 0043812838495a45449a0ac61a81b9c16eddca1ad249fb4f7fdb1c4505e9bb34
            // has sections named ".data\x00l\x06" and ".bss\x00\x7f".
            let name = BStr::new(name).trim_end_with(|c| c == '\0');

            let mut section = pe::Section::new();

            section.name = Some(name.into());
            section.characteristics = Some(characteristics);
            section.raw_data_size = Some(raw_data_size);
            section.raw_data_offset = Some(raw_data_offset);
            section.virtual_address = Some(virtual_address);
            section.virtual_size = Some(virtual_size);
            section.pointer_to_relocations = Some(pointer_to_relocations);
            section.pointer_to_line_numbers = Some(pointer_to_line_numbers);
            section.number_of_relocations = Some(number_of_relocations.into());
            section.number_of_line_numbers =
                Some(number_of_line_numbers.into());

            self.result.sections.push(section);

            Ok((remainder, ()))
        }
    }

    /// Returns the offset where the last PE section ends.
    fn end_of_last_section(&self) -> Option<u64> {
        self.result
            .sections
            .iter()
            .map(|section| {
                section.raw_data_offset.unwrap() as u64
                    + section.raw_data_size.unwrap() as u64
            })
            .max()
    }

    /// Parse the rich header
    ///
    /// http://www.ntcore.com/files/richsign.htm
    /// https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/
    fn parse_rich_signature(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            // Search for the "Rich" tag that indicates the end of the rich
            // data. The tag is searched starting at the end of the input and
            // going backwards.
            let rich_tag_pos = memmem::rfind(input, Self::RICH_TAG).ok_or(
                Err::Error(nom::error::Error::new(input, ErrorKind::Tag)),
            )?;

            // The u32 that follows the "Rich" tag is the XOR key used for
            // for encrypting the Rich data.
            let (remainder, xor_key) = le_u32(&input[rich_tag_pos + 4..])?;

            // Search for the "Dans" tag that indicates the start of the rich
            // data. This tag is encrypted with the XOR key.
            let dans_tag = xor_key ^ 0x536e6144;

            let dans_tag_pos = memmem::rfind(
                &input[..rich_tag_pos],
                dans_tag.to_le_bytes().as_slice(),
            )
            .ok_or(Err::Error(nom::error::Error::new(
                &input[..rich_tag_pos],
                ErrorKind::Tag,
            )))?;

            let rich_data = &input[dans_tag_pos..rich_tag_pos];
            let mut clear_data: Vec<u8> = rich_data.to_owned();

            // Decrypt the rich data by XORing each byte in the data with
            // the byte corresponding byte in the key.
            for (data_byte, key_byte) in zip(
                clear_data.iter_mut(),
                xor_key.to_le_bytes().iter().cycle(),
            ) {
                *data_byte ^= key_byte;
            }

            self.result.rich_signature =
                MessageField::some(pe::RichSignature {
                    offset: Some(dans_tag_pos.try_into().unwrap()),
                    length: Some(rich_data.len().try_into().unwrap()),
                    key: Some(xor_key),
                    // TODO: implement some mechanism for returning slices
                    // backed by the scanned data without copy.
                    raw_data: Some(rich_data.to_vec()),
                    clear_data: Some(clear_data),
                    special_fields: Default::default(),
                });

            Ok((remainder, ()))
        }
    }
}

struct DirEntry {
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
