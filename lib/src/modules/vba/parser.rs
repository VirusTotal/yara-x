use nom::{
    Parser,
    bytes::complete::take,
    combinator::verify,
    number::complete::{le_u16, le_u32},
};
use std::collections::HashMap;

pub enum ModuleType {
    Standard,
    Class,
    Unknown,
}

pub struct ProjectInfo {
    pub name: String,
    pub version: String,
    pub references: Vec<String>,
}

pub struct VbaModule {
    pub name: String,
    pub code: String,
    pub module_type: ModuleType,
}

pub struct VbaProject {
    pub modules: HashMap<String, VbaModule>,
    pub info: ProjectInfo,
}

impl VbaProject {
    fn copytoken_help(difference: usize) -> (u16, u16, u32, u16) {
        let bit_count = (difference as f64).log2().ceil() as u32;
        let bit_count = bit_count.max(4);
        let length_mask = 0xFFFF >> bit_count;
        let offset_mask = !length_mask;
        let maximum_length = (0xFFFF >> bit_count) + 3;

        (length_mask, offset_mask, bit_count, maximum_length)
    }

    pub fn decompress_stream(
        compressed: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if compressed.is_empty() {
            return Err("Empty input buffer");
        }

        if compressed[0] != 0x01 {
            return Err("Invalid signature byte");
        }

        let mut decompressed = Vec::with_capacity(compressed.len() * 2);
        let mut current = 1; // Skip signature byte

        while current < compressed.len() {
            // We need 2 bytes for the chunk header
            if current + 2 > compressed.len() {
                return Err("Incomplete chunk header");
            }

            let chunk_header = u16::from_le_bytes(
                compressed[current..current + 2]
                    .try_into()
                    .map_err(|_| "Failed to parse chunk header")?,
            );
            let chunk_size = (chunk_header & 0x0FFF) as usize + 3;
            let chunk_is_compressed = (chunk_header & 0x8000) != 0;

            current += 2;

            if chunk_is_compressed && chunk_size > 4095 {
                return Err(
                    "CompressedChunkSize > 4095 but CompressedChunkFlag == 1",
                );
            }
            if !chunk_is_compressed && chunk_size != 4095 {
                return Err(
                    "CompressedChunkSize != 4095 but CompressedChunkFlag == 0",
                );
            }

            let chunk_end =
                std::cmp::min(compressed.len(), current + chunk_size);

            if !chunk_is_compressed {
                if current + 4096 > compressed.len() {
                    return Err("Incomplete uncompressed chunk");
                }
                decompressed
                    .extend_from_slice(&compressed[current..current + 4096]);
                current += 4096;
                continue;
            }

            let decompressed_chunk_start = decompressed.len();

            while current < chunk_end {
                let flag_byte = compressed[current];
                current += 1;

                for bit_index in 0..8 {
                    if current >= chunk_end {
                        break;
                    }

                    if (flag_byte & (1 << bit_index)) == 0 {
                        decompressed.push(compressed[current]);
                        current += 1;
                    } else {
                        if current + 2 > compressed.len() {
                            return Err("Incomplete copy token");
                        }

                        let copy_token = u16::from_le_bytes(
                            compressed[current..current + 2]
                                .try_into()
                                .map_err(|_| "Failed to parse copy token")?,
                        );
                        let (length_mask, offset_mask, bit_count, _) =
                            Self::copytoken_help(
                                decompressed.len() - decompressed_chunk_start,
                            );

                        let length = (copy_token & length_mask) + 3;
                        let temp1 = copy_token & offset_mask;
                        let temp2 = 16 - bit_count;
                        let offset = (temp1 >> temp2) + 1;

                        if offset as usize > decompressed.len() {
                            return Err("Invalid copy token offset");
                        }

                        let copy_source = decompressed.len() - offset as usize;
                        for i in 0..length {
                            let source_idx = copy_source + i as usize;
                            if source_idx >= decompressed.len() {
                                return Err("Copy token source out of bounds");
                            }
                            decompressed.push(decompressed[source_idx]);
                        }
                        current += 2;
                    }
                }
            }
        }

        Ok(decompressed)
    }

    fn parse_record<'c, P, O>(
        mut parser: P,
        input: &'c [u8],
        err_msg: &'static str,
    ) -> Result<(&'c [u8], O), &'static str>
    where
        P: Parser<&'c [u8], Output = O, Error = nom::error::Error<&'c [u8]>>,
    {
        parser.parse(input).map_err(|_| err_msg)
    }

    pub fn parse(
        compressed_dir_stream: &[u8],
        module_streams: HashMap<String, Vec<u8>>,
    ) -> Result<Self, &'static str> {
        let dir_stream = Self::decompress_stream(compressed_dir_stream)?;
        let input = &dir_stream[..];

        // -- PROJECTSYSKIND Record
        // Specifies the operating system platform for the VBA project.
        // See: [MS-OVBA] Section 2.3.4.2.1.1 PROJECTSYSKIND Record
        // Landing page: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/571360c7-d1a8-44d4-9d5f-f32a4e210168
        let (input, _) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0001),
                verify(le_u32, |&size| size == 0x0004),
                le_u32,
            ),
            input,
            "Failed to parse PROJECTSYSKIND Record",
        )?;

        // -- PROJECTCOMPATVERSION Record (Optional)
        // Specifies the compatibility version of the VBA project. Introduced in Office 2010.
        // See: [MS-OVBA] Section 2.3.4.2.1.12 PROJECTCOMPATVERSION Record
        let mut remainder = input;
        let (peek_input, next_id) =
            Self::parse_record(le_u16, input, "Failed to peek next ID")?;
        if next_id == 0x004A {
            let (remainder, _) = Self::parse_record(
                (
                    le_u16, // id (0x004A)
                    verify(le_u32, |&size| size == 0x0004),
                    le_u32, // compatibility version
                ),
                input,
                "Failed to parse PROJECTCOMPATVERSION Record",
            )?;
        }
        let input = remainder;

        // -- PROJECTLCID Record
        // Specifies the VBA project's LCID (Locale Identifier).
        // See: [MS-OVBA] Section 2.3.4.2.1.2 PROJECTLCID Record
        let (input, _) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0002),
                verify(le_u32, |&size| size == 0x0004),
                verify(le_u32, |&val| val == 0x409),
            ),
            input,
            "Failed to parse PROJECTLCID Record",
        )?;

        // -- PROJECTLCIDINVOKE Record
        // Specifies the VBA project's LCID for invoking APIs.
        // See: [MS-OVBA] Section 2.3.4.2.1.3 PROJECTLCIDINVOKE Record
        let (input, _) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0014),
                verify(le_u32, |&size| size == 0x0004),
                verify(le_u32, |&val| val == 0x409),
            ),
            input,
            "Failed to parse PROJECTLCIDINVOKE Record",
        )?;

        // -- PROJECTCODEPAGE Record
        // Specifies the codepage to be used for string decoding in the project.
        // See: [MS-OVBA] Section 2.3.4.2.1.4 PROJECTCODEPAGE Record
        let (input, _) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0003),
                verify(le_u32, |&size| size == 0x0002),
                le_u16,
            ),
            input,
            "Failed to parse PROJECTCODEPAGE Record",
        )?;

        // -- PROJECTNAME Record
        // Specifies the VBA project name.
        // See: [MS-OVBA] Section 2.3.4.2.1.5 PROJECTNAME Record
        let (input, (_, name_size)) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0004),
                verify(le_u32, |&size| (1..=128).contains(&size)),
            ),
            input,
            "Failed to parse PROJECTNAME Record header",
        )?;

        let (input, name_bytes) = Self::parse_record(
            take(name_size as usize),
            input,
            "Failed to parse PROJECTNAME bytes",
        )?;

        let project_name = String::from_utf8_lossy(name_bytes).to_string();

        // -- PROJECTDOCSTRING Record
        // Specifies the project description and its Unicode equivalent.
        // See: [MS-OVBA] Section 2.3.4.2.1.6 PROJECTDOCSTRING Record
        let (input, (_, doc_size)) = Self::parse_record(
            (verify(le_u16, |&id| id == 0x0005), le_u32),
            input,
            "Failed to parse PROJECTDOCSTRING Record header",
        )?;

        let (input, _doc_string) = Self::parse_record(
            take(doc_size as usize),
            input,
            "Failed to parse PROJECTDOCSTRING bytes",
        )?;

        let (input, (_, doc_unicode_size)) = Self::parse_record(
            (
                verify(le_u16, |&reserved| reserved == 0x0040),
                verify(le_u32, |&size| size.is_multiple_of(2)),
            ),
            input,
            "Failed to parse PROJECTDOCSTRING Unicode header",
        )?;

        let (input, _doc_unicode) = Self::parse_record(
            take(doc_unicode_size as usize),
            input,
            "Failed to parse PROJECTDOCSTRING Unicode bytes",
        )?;

        // -- PROJECTHELPFILEPATH Record
        // Specifies help file paths for the VBA project.
        // See: [MS-OVBA] Section 2.3.4.2.1.7 PROJECTHELPFILEPATH Record
        let (input, (_, helpfile_size1)) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0006),
                verify(le_u32, |&size| size <= 260),
            ),
            input,
            "Failed to parse PROJECTHELPFILEPATH Record header",
        )?;

        let (input, helpfile1) = Self::parse_record(
            take(helpfile_size1 as usize),
            input,
            "Failed to parse PROJECTHELPFILEPATH bytes 1",
        )?;

        let (input, (_, helpfile_size2)) = Self::parse_record(
            (
                verify(le_u16, |&reserved| reserved == 0x003D),
                verify(le_u32, |&size| size == helpfile_size1),
            ),
            input,
            "Failed to parse PROJECTHELPFILEPATH Unicode header",
        )?;

        let (input, helpfile2) = Self::parse_record(
            take(helpfile_size2 as usize),
            input,
            "Failed to parse PROJECTHELPFILEPATH bytes 2",
        )?;

        if helpfile1 != helpfile2 {
            return Err("Help files don't match");
        }

        // -- PROJECTHELPCONTEXT Record
        // Specifies the help context ID in the help file.
        // See: [MS-OVBA] Section 2.3.4.2.1.8 PROJECTHELPCONTEXT Record
        let (input, _) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0007),
                verify(le_u32, |&size| size == 0x0004),
                le_u32,
            ),
            input,
            "Failed to parse PROJECTHELPCONTEXT Record",
        )?;

        // -- PROJECTLIBFLAGS Record
        // Specifies the library flags of the VBA project.
        // See: [MS-OVBA] Section 2.3.4.2.1.9 PROJECTLIBFLAGS Record
        let (input, _) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0008),
                verify(le_u32, |&size| size == 0x0004),
                verify(le_u32, |&flags| flags == 0x0000),
            ),
            input,
            "Failed to parse PROJECTLIBFLAGS Record",
        )?;

        // -- PROJECTVERSION Record
        // Specifies the major and minor version of the VBA project.
        // See: [MS-OVBA] Section 2.3.4.2.1.10 PROJECTVERSION Record
        let (input, (_, _, version_major, version_minor)) =
            Self::parse_record(
                (
                    verify(le_u16, |&id| id == 0x0009),
                    verify(le_u32, |&reserved| reserved == 0x0004),
                    le_u32,
                    le_u16,
                ),
                input,
                "Failed to parse PROJECTVERSION Record",
            )?;

        // -- PROJECTCONSTANTS Record
        // Specifies compilation constants of the VBA project.
        // See: [MS-OVBA] Section 2.3.4.2.1.11 PROJECTCONSTANTS Record
        let (input, (_, constants_size)) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x000C),
                verify(le_u32, |&size| size <= 1015),
            ),
            input,
            "Failed to parse PROJECTCONSTANTS Record header",
        )?;

        let (input, _constants) = Self::parse_record(
            take(constants_size as usize),
            input,
            "Failed to parse PROJECTCONSTANTS bytes",
        )?;

        let (input, (_, constants_unicode_size)) = Self::parse_record(
            (
                verify(le_u16, |&reserved| reserved == 0x003C),
                verify(le_u32, |&size| size.is_multiple_of(2)),
            ),
            input,
            "Failed to parse PROJECTCONSTANTS Unicode header",
        )?;

        let (input, _constants_unicode) = Self::parse_record(
            take(constants_unicode_size as usize),
            input,
            "Failed to parse PROJECTCONSTANTS Unicode bytes",
        )?;

        // -- References
        // Parses references to libraries, controls, and other projects.
        // See: [MS-OVBA] Section 2.3.4.2.2 References Record
        let (input, references) = Self::parse_references(input)?;

        // -- PROJECTMODULES Record
        // Specifies module block count of the project.
        // See: [MS-OVBA] Section 2.3.4.2.3 PROJECTMODULES Record
        let (input, _) = Self::parse_record(
            verify(le_u32, |&size| size == 0x0002),
            input,
            "Failed to parse PROJECTMODULES_Size",
        )?;

        let (input, modules_count) = Self::parse_record(
            le_u16,
            input,
            "Failed to parse PROJECTMODULES_Count",
        )?;

        // -- ProjectCookie Record
        // Specifies the project cookie record.
        // See: [MS-OVBA] Section 2.3.4.2.3.1 ProjectCookie Record
        let (input, _) = Self::parse_record(
            (
                verify(le_u16, |&id| id == 0x0013),
                verify(le_u32, |&size| size == 0x0002),
                le_u16,
            ),
            input,
            "Failed to parse ProjectCookie Record",
        )?;

        // -- Modules
        // Parses module streams and decompresses MS-OVBA streams.
        // See: [MS-OVBA] Section 2.3.4.2.3.2 Modules
        let (_input, modules) =
            Self::parse_modules(input, modules_count, &module_streams)?;

        Ok(VbaProject {
            modules,
            info: ProjectInfo {
                name: project_name,
                version: format!("{}.{}", version_major, version_minor),
                references,
            },
        })
    }

    fn parse_references(
        mut input: &[u8],
    ) -> Result<(&[u8], Vec<String>), &'static str> {
        let mut references = Vec::new();
        loop {
            let (remainder, check) = Self::parse_record(
                le_u16,
                input,
                "Failed to parse reference type check",
            )?;
            input = remainder;
            if check == 0x000F {
                break;
            }

            match check {
                0x0016 => {
                    // REFERENCE Name
                    let (remainder, name_size) = Self::parse_record(
                        le_u32,
                        input,
                        "Failed to parse name size",
                    )?;
                    let (remainder, name_bytes) = Self::parse_record(
                        take(name_size as usize),
                        remainder,
                        "Failed to parse name bytes",
                    )?;
                    let name = String::from_utf8_lossy(name_bytes).to_string();
                    references.push(name);

                    let (remainder, (reserved, unicode_size)) =
                        Self::parse_record(
                            (verify(le_u16, |&val| val == 0x003E), le_u32),
                            remainder,
                            "Failed to parse Unicode reference header",
                        )?;
                    let (remainder, _name_unicode) = Self::parse_record(
                        take(unicode_size as usize),
                        remainder,
                        "Failed to parse Unicode name bytes",
                    )?;
                    input = remainder;
                }
                0x0033 => {
                    // REFERENCEORIGINAL
                    let (remainder, size) = Self::parse_record(
                        le_u32,
                        input,
                        "Failed to parse REFERENCEORIGINAL size",
                    )?;
                    let (remainder, _libid) = Self::parse_record(
                        take(size as usize),
                        remainder,
                        "Failed to parse REFERENCEORIGINAL bytes",
                    )?;
                    input = remainder;
                }
                0x002F => {
                    // REFERENCECONTROL
                    let (remainder, size_twiddled) = Self::parse_record(
                        le_u32,
                        input,
                        "Failed to parse size_twiddled",
                    )?;
                    let (remainder, _twiddled) = Self::parse_record(
                        take(size_twiddled as usize),
                        remainder,
                        "Failed to parse twiddled bytes",
                    )?;

                    let (remainder, _) = Self::parse_record(
                        (
                            verify(le_u32, |&val| val == 0x0000),
                            verify(le_u16, |&val| val == 0x0000),
                        ),
                        remainder,
                        "Failed to parse REFERENCECONTROL reserved header",
                    )?;

                    let (remainder, maybe_check2) = Self::parse_record(
                        le_u16,
                        remainder,
                        "Failed to parse REFERENCECONTROL name-record option check",
                    )?;
                    if maybe_check2 == 0x0016 {
                        // Name record
                        let (remainder, name_size) = Self::parse_record(
                            le_u32,
                            remainder,
                            "Failed to parse NameRecord size",
                        )?;
                        let (remainder, _name) = Self::parse_record(
                            take(name_size as usize),
                            remainder,
                            "Failed to parse NameRecord bytes",
                        )?;

                        let (remainder, (reserved, unicode_size)) =
                            Self::parse_record(
                                (verify(le_u16, |&val| val == 0x003E), le_u32),
                                remainder,
                                "Failed to parse NameRecord Unicode header",
                            )?;
                        let (remainder, _name_unicode) = Self::parse_record(
                            take(unicode_size as usize),
                            remainder,
                            "Failed to parse NameRecord Unicode bytes",
                        )?;

                        let (remainder, _) = Self::parse_record(
                            verify(le_u16, |&val| val == 0x0030),
                            remainder,
                            "Failed to parse REFERENCECONTROL Reserved3",
                        )?;
                        input = remainder;
                    } else {
                        // No name record, maybe_check2 is reserved3
                        if maybe_check2 != 0x0030 {
                            return Err("Invalid REFERENCECONTROL_Reserved3");
                        }
                        input = remainder;
                    }

                    let (remainder, (_size_extended, size_libid)) =
                        Self::parse_record(
                            (le_u32, le_u32),
                            input,
                            "Failed to parse extended libid sizes",
                        )?;
                    let (remainder, _libid) = Self::parse_record(
                        take(size_libid as usize),
                        remainder,
                        "Failed to parse libid bytes",
                    )?;
                    let (remainder, _) = Self::parse_record(
                        (le_u32, le_u16),
                        remainder,
                        "Failed to parse REFERENCECONTROL reserved tails",
                    )?;
                    let (remainder, _original_typelib) = Self::parse_record(
                        take(16_usize),
                        remainder,
                        "Failed to parse original typelib bytes",
                    )?;
                    let (remainder, _cookie) = Self::parse_record(
                        le_u32,
                        remainder,
                        "Failed to parse cookie",
                    )?;
                    input = remainder;
                }
                0x000D => {
                    // REFERENCEREGISTERED
                    let (remainder, (_size, libid_size)) = Self::parse_record(
                        (le_u32, le_u32),
                        input,
                        "Failed to parse REFERENCEREGISTERED sizes",
                    )?;
                    let (remainder, _libid) = Self::parse_record(
                        take(libid_size as usize),
                        remainder,
                        "Failed to parse REFERENCEREGISTERED libid bytes",
                    )?;
                    let (remainder, _) = Self::parse_record(
                        (
                            verify(le_u32, |&val| val == 0x0000),
                            verify(le_u16, |&val| val == 0x0000),
                        ),
                        remainder,
                        "Failed to parse REFERENCEREGISTERED reserved tails",
                    )?;
                    input = remainder;
                }
                0x000E => {
                    // REFERENCEPROJECT
                    let (remainder, (_size, libid_abs_size)) =
                        Self::parse_record(
                            (le_u32, le_u32),
                            input,
                            "Failed to parse REFERENCEPROJECT libid abs sizes",
                        )?;
                    let (remainder, _libid_abs) = Self::parse_record(
                        take(libid_abs_size as usize),
                        remainder,
                        "Failed to parse REFERENCEPROJECT libid abs bytes",
                    )?;
                    let (remainder, libid_rel_size) = Self::parse_record(
                        le_u32,
                        remainder,
                        "Failed to parse REFERENCEPROJECT libid rel size",
                    )?;
                    let (remainder, _libid_rel) = Self::parse_record(
                        take(libid_rel_size as usize),
                        remainder,
                        "Failed to parse REFERENCEPROJECT libid rel bytes",
                    )?;
                    let (remainder, (_major, _minor)) = Self::parse_record(
                        (le_u32, le_u16),
                        remainder,
                        "Failed to parse major/minor versions",
                    )?;
                    input = remainder;
                }
                _ => return Err("Invalid reference type"),
            }
        }
        Ok((input, references))
    }

    fn parse_modules<'c>(
        mut input: &'c [u8],
        modules_count: u16,
        module_streams: &HashMap<String, Vec<u8>>,
    ) -> Result<(&'c [u8], HashMap<String, VbaModule>), &'static str> {
        let mut modules = HashMap::new();

        for _ in 0..modules_count {
            // MODULENAME record
            let (remainder, _) = Self::parse_record(
                verify(le_u16, |&id| id == 0x0019),
                input,
                "Failed to parse MODULENAME_Id",
            )?;

            let (remainder, module_name_size) = Self::parse_record(
                le_u32,
                remainder,
                "Failed to parse module name size",
            )?;
            let (remainder, name_bytes) = Self::parse_record(
                take(module_name_size as usize),
                remainder,
                "Failed to parse module name bytes",
            )?;
            let module_name = String::from_utf8_lossy(name_bytes).to_string();
            input = remainder;

            let mut module_type = ModuleType::Unknown;
            let mut stream_name = String::new();
            let mut module_offset = 0u32;

            // Read sections until terminator 0x002B
            loop {
                let (remainder, section_id) = Self::parse_record(
                    le_u16,
                    input,
                    "Failed to parse module section ID",
                )?;
                input = remainder;
                match section_id {
                    0x0047 => {
                        // MODULENAMEUNICODE
                        let (remainder, unicode_size) = Self::parse_record(
                            le_u32,
                            input,
                            "Failed to parse MODULENAMEUNICODE size",
                        )?;
                        let (remainder, _unicode_name) = Self::parse_record(
                            take(unicode_size as usize),
                            remainder,
                            "Failed to parse MODULENAMEUNICODE bytes",
                        )?;
                        input = remainder;
                    }
                    0x001A => {
                        // MODULESTREAMNAME
                        let (remainder, stream_size) = Self::parse_record(
                            le_u32,
                            input,
                            "Failed to parse STREAMNAME size",
                        )?;
                        let (remainder, stream_bytes) = Self::parse_record(
                            take(stream_size as usize),
                            remainder,
                            "Failed to parse STREAMNAME bytes",
                        )?;
                        stream_name =
                            String::from_utf8_lossy(stream_bytes).to_string();

                        let (remainder, _) = Self::parse_record(
                            verify(le_u16, |&val| val == 0x0032),
                            remainder,
                            "Failed to parse STREAMNAME reserved flag",
                        )?;

                        let (remainder, unicode_size) = Self::parse_record(
                            le_u32,
                            remainder,
                            "Failed to parse STREAMNAME Unicode size",
                        )?;
                        let (remainder, _unicode_name) = Self::parse_record(
                            take(unicode_size as usize),
                            remainder,
                            "Failed to parse STREAMNAME Unicode bytes",
                        )?;
                        input = remainder;
                    }
                    0x001C => {
                        // MODULEDOCSTRING
                        let (remainder, doc_size) = Self::parse_record(
                            le_u32,
                            input,
                            "Failed to parse MODULEDOCSTRING size",
                        )?;
                        let (remainder, _doc_string) = Self::parse_record(
                            take(doc_size as usize),
                            remainder,
                            "Failed to parse MODULEDOCSTRING bytes",
                        )?;

                        let (remainder, _) = Self::parse_record(
                            verify(le_u16, |&val| val == 0x0048),
                            remainder,
                            "Failed to parse MODULEDOCSTRING reserved flag",
                        )?;

                        let (remainder, unicode_size) = Self::parse_record(
                            le_u32,
                            remainder,
                            "Failed to parse MODULEDOCSTRING Unicode size",
                        )?;
                        let (remainder, _unicode_doc) = Self::parse_record(
                            take(unicode_size as usize),
                            remainder,
                            "Failed to parse MODULEDOCSTRING Unicode bytes",
                        )?;
                        input = remainder;
                    }
                    0x0031 => {
                        // MODULEOFFSET
                        let (remainder, offset_size) = Self::parse_record(
                            verify(le_u32, |&size| size == 0x0004),
                            input,
                            "Failed to parse MODULEOFFSET size",
                        )?;
                        let (remainder, offset) = Self::parse_record(
                            le_u32,
                            remainder,
                            "Failed to parse MODULEOFFSET value",
                        )?;
                        module_offset = offset;
                        input = remainder;
                    }
                    0x001E => {
                        // MODULEHELPCONTEXT
                        let (remainder, help_size) = Self::parse_record(
                            verify(le_u32, |&size| size == 0x0004),
                            input,
                            "Failed to parse MODULEHELPCONTEXT size",
                        )?;
                        let (remainder, _help_context) = Self::parse_record(
                            le_u32,
                            remainder,
                            "Failed to parse MODULEHELPCONTEXT value",
                        )?;
                        input = remainder;
                    }
                    0x002C => {
                        // MODULECOOKIE
                        let (remainder, cookie_size) = Self::parse_record(
                            verify(le_u32, |&size| size == 0x0002),
                            input,
                            "Failed to parse MODULECOOKIE size",
                        )?;
                        let (remainder, _cookie) = Self::parse_record(
                            le_u16,
                            remainder,
                            "Failed to parse MODULECOOKIE value",
                        )?;
                        input = remainder;
                    }
                    0x0021 => {
                        module_type = ModuleType::Standard;
                        let (remainder, _) = Self::parse_record(
                            le_u32,
                            input,
                            "Failed to parse standard module reserve",
                        )?;
                        input = remainder;
                    }
                    0x0022 => {
                        module_type = ModuleType::Class;
                        let (remainder, _) = Self::parse_record(
                            le_u32,
                            input,
                            "Failed to parse class module reserve",
                        )?;
                        input = remainder;
                    }
                    0x0025 => {
                        let (remainder, _) = Self::parse_record(
                            verify(le_u32, |&val| val == 0x0000),
                            input,
                            "Failed to parse READONLY reserved",
                        )?;
                        input = remainder;
                    }
                    0x0028 => {
                        let (remainder, _) = Self::parse_record(
                            verify(le_u32, |&val| val == 0x0000),
                            input,
                            "Failed to parse PRIVATE reserved",
                        )?;
                        input = remainder;
                    }
                    0x002B => {
                        // TERMINATOR
                        let (remainder, _) = Self::parse_record(
                            verify(le_u32, |&val| val == 0x0000),
                            input,
                            "Failed to parse TERMINATOR reserved",
                        )?;
                        input = remainder;
                        break;
                    }
                    _ => return Err("Invalid module section ID"),
                }
            }

            // Retrieve module code
            if let Some(module_data) = module_streams.get(&stream_name) {
                if module_offset as usize >= module_data.len() {
                    return Err("Invalid module offset");
                }
                let code_data = &module_data[module_offset as usize..];
                if !code_data.is_empty() {
                    let decompressed =
                        VbaProject::decompress_stream(code_data)?;
                    let code =
                        String::from_utf8_lossy(&decompressed).to_string();
                    modules.insert(
                        module_name.clone(),
                        VbaModule { name: module_name, code, module_type },
                    );
                }
            }
        }

        Ok((input, modules))
    }
}
