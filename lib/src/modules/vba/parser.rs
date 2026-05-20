use nom::combinator::opt;
use nom::multi::length_data;
use nom::{
    Parser,
    bytes::complete::take,
    combinator::verify,
    number::complete::{le_u16, le_u32},
};
use std::collections::HashMap;

use crate::modules::protos::vba::vba::ProjectInfo;
use crate::modules::protos::vba::{ModuleType, Vba};

type Error<'a> = nom::error::Error<&'a [u8]>;

fn copytoken_help(difference: usize) -> (u16, u16, u32, u16) {
    let bit_count = (difference as f64).log2().ceil() as u32;
    let bit_count = bit_count.max(4);
    let length_mask = 0xFFFF >> bit_count;
    let offset_mask = !length_mask;
    let maximum_length = (0xFFFF >> bit_count) + 3;

    (length_mask, offset_mask, bit_count, maximum_length)
}

pub fn decompress_stream(compressed: &[u8]) -> Result<Vec<u8>, &'static str> {
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

        let chunk_end = std::cmp::min(compressed.len(), current + chunk_size);

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
                        copytoken_help(
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

pub fn parse(
    compressed_dir_stream: &[u8],
    module_streams: HashMap<String, Vec<u8>>,
) -> Result<Vba, &'static str> {
    let dir_stream = decompress_stream(compressed_dir_stream)?;
    let mut vba = Vba::new();
    parse_inner(&dir_stream, &module_streams, &mut vba)
        .map_err(|_| "Failed to parse VBA dir stream")?;
    Ok(vba)
}

fn parse_inner<'a>(
    dir_stream: &'a [u8],
    module_streams: &HashMap<String, Vec<u8>>,
    vba: &mut Vba,
) -> Result<(), nom::Err<Error<'a>>> {
    let input = dir_stream;

    // The records below are described in [MS-OVBA] version 15.0.
    // https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc

    // -- PROJECTSYSKIND Record
    // Specifies the operating system platform for the VBA project.
    // See: [MS-OVBA] Section 2.3.4.2.1.1 PROJECTSYSKIND Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0001),
        verify(le_u32, |&size| size == 0x0004),
        le_u32,
    )
        .parse(input)?;

    // -- PROJECTCOMPATVERSION Record (Optional)
    // Specifies the compatibility version of the VBA project. Introduced in Office 2010.
    // See: [MS-OVBA] Section 2.3.4.2.1.2 PROJECTCOMPATVERSION Record
    let (input, _) = opt((
        verify(le_u16, |&id| id == 0x004A),
        verify(le_u32, |&size| size == 0x0004),
        le_u32,
    ))
    .parse(input)?;

    // -- PROJECTLCID Record
    // Specifies the VBA project's LCID (Locale Identifier).
    // See: [MS-OVBA] Section 2.3.4.2.1.3 PROJECTLCID Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0002),
        verify(le_u32, |&size| size == 0x0004),
        verify(le_u32, |&val| val == 0x409),
    )
        .parse(input)?;

    // -- PROJECTLCIDINVOKE Record
    // Specifies the VBA project's LCID for invoking APIs.
    // See: [MS-OVBA] Section 2.3.4.2.1.4 PROJECTLCIDINVOKE Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0014),
        verify(le_u32, |&size| size == 0x0004),
        verify(le_u32, |&val| val == 0x409),
    )
        .parse(input)?;

    // -- PROJECTCODEPAGE Record
    // Specifies the codepage to be used for string decoding in the project.
    // See: [MS-OVBA] Section 2.3.4.2.1.5 PROJECTCODEPAGE Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0003),
        verify(le_u32, |&size| size == 0x0002),
        le_u16,
    )
        .parse(input)?;

    // -- PROJECTNAME Record
    // Specifies the VBA project name.
    // See: [MS-OVBA] Section 2.3.4.2.1.6 PROJECTNAME Record
    let (input, (_, project_name)) = (
        verify(le_u16, |&id| id == 0x0004),
        length_data(verify(le_u32, |&size| (1..=128).contains(&size)))
            .map(String::from_utf8_lossy),
    )
        .parse(input)?;

    // -- PROJECTDOCSTRING Record
    // Specifies the project description and its Unicode equivalent.
    // See: [MS-OVBA] Section 2.3.4.2.1.7 PROJECTDOCSTRING Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0005),
        length_data(le_u32),
        verify(le_u16, |&reserved| reserved == 0x0040),
        length_data(verify(le_u32, |&size| size % 2 == 0)),
    )
        .parse(input)?;

    // -- PROJECTHELPFILEPATH Record
    // Specifies help file paths for the VBA project.
    // See: [MS-OVBA] Section 2.3.4.2.1.8 PROJECTHELPFILEPATH Record
    let (input, (_, helpfile1, _, helpfile2)) = (
        verify(le_u16, |&id| id == 0x0006),
        length_data(verify(le_u32, |&size| size <= 260)),
        verify(le_u16, |&reserved| reserved == 0x003D),
        length_data(verify(le_u32, |&size| size <= 260)),
    )
        .parse(input)?;

    if helpfile1 != helpfile2 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    // -- PROJECTHELPCONTEXT Record
    // Specifies the help context ID in the help file.
    // See: [MS-OVBA] Section 2.3.4.2.1.9 PROJECTHELPCONTEXT Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0007),
        verify(le_u32, |&size| size == 0x0004),
        le_u32,
    )
        .parse(input)?;

    // -- PROJECTLIBFLAGS Record
    // Specifies the library flags of the VBA project.
    // See: [MS-OVBA] Section 2.3.4.2.1.10 PROJECTLIBFLAGS Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0008),
        verify(le_u32, |&size| size == 0x0004),
        verify(le_u32, |&flags| flags == 0x0000),
    )
        .parse(input)?;

    // -- PROJECTVERSION Record
    // Specifies the major and minor version of the VBA project.
    // See: [MS-OVBA] Section 2.3.4.2.1.11 PROJECTVERSION Record
    let (input, (_, _, version_major, version_minor)) = (
        verify(le_u16, |&id| id == 0x0009),
        verify(le_u32, |&reserved| reserved == 0x0004),
        le_u32,
        le_u16,
    )
        .parse(input)?;

    // -- PROJECTCONSTANTS Record
    // Specifies compilation constants of the VBA project.
    // See: [MS-OVBA] Section 2.3.4.2.1.12 PROJECTCONSTANTS Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x000C),
        length_data(verify(le_u32, |&size| size <= 1015)),
        verify(le_u16, |&reserved| reserved == 0x003C),
        length_data(verify(le_u32, |&size| size % 2 == 0)),
    )
        .parse(input)?;

    // -- References
    // Parses references to libraries, controls, and other projects.
    // See: [MS-OVBA] Section 2.3.4.2.2 References Record
    let (input, references) = parse_references(input)?;

    // -- PROJECTMODULES Record
    // Specifies module block count of the project.
    // See: [MS-OVBA] Section 2.3.4.2.3 PROJECTMODULES Record
    let (input, (_, modules_count)) =
        (verify(le_u32, |&size| size == 0x0002), le_u16).parse(input)?;

    // -- ProjectCookie Record
    // Specifies the project cookie record.
    // See: [MS-OVBA] Section 2.3.4.2.3.1 ProjectCookie Record
    let (input, _) = (
        verify(le_u16, |&id| id == 0x0013),
        verify(le_u32, |&size| size == 0x0002),
        le_u16,
    )
        .parse(input)?;

    // -- Modules
    // Parses module streams and decompresses MS-OVBA streams.
    // See: [MS-OVBA] Section 2.3.4.2.3.2 Modules
    let (_input, _) =
        parse_modules(input, modules_count, module_streams, vba)?;

    let mut project_info = ProjectInfo::new();
    project_info.references = references;

    project_info.set_name(project_name.to_string());
    project_info.set_version(format!("{}.{}", version_major, version_minor));
    project_info.set_module_count(modules_count as i32);
    project_info.set_is_compressed(true);

    vba.project_info = protobuf::MessageField::some(project_info);

    Ok(())
}

fn parse_references(
    mut input: &[u8],
) -> Result<(&[u8], Vec<String>), nom::Err<Error<'_>>> {
    let mut references = Vec::new();
    loop {
        let (remainder, check) = le_u16.parse(input)?;
        input = remainder;
        if check == 0x000F {
            break;
        }

        match check {
            0x0016 => {
                // REFERENCE Name
                let (remainder, name) = length_data(le_u32)
                    .map(String::from_utf8_lossy)
                    .parse(input)?;

                references.push(name.to_string());

                let (remainder, _) =
                    verify(le_u16, |&val| val == 0x003E).parse(remainder)?;
                let (remainder, _) = length_data(le_u32).parse(remainder)?;
                input = remainder;
            }
            0x0033 => {
                // REFERENCEORIGINAL
                let (remainder, _) = length_data(le_u32).parse(input)?;
                input = remainder;
            }
            0x002F => {
                // REFERENCECONTROL
                let (remainder, _) = length_data(le_u32).parse(input)?;

                let (remainder, _) = (
                    verify(le_u32, |&val| val == 0x0000),
                    verify(le_u16, |&val| val == 0x0000),
                )
                    .parse(remainder)?;

                let (remainder, maybe_check2) = le_u16.parse(remainder)?;
                if maybe_check2 == 0x0016 {
                    // Name record
                    let (remainder, _) =
                        length_data(le_u32).parse(remainder)?;

                    let (remainder, _) = verify(le_u16, |&val| val == 0x003E)
                        .parse(remainder)?;
                    let (remainder, _) =
                        length_data(le_u32).parse(remainder)?;

                    let (remainder, _) = verify(le_u16, |&val| val == 0x0030)
                        .parse(remainder)?;
                    input = remainder;
                } else {
                    // No name record, maybe_check2 is reserved3
                    if maybe_check2 != 0x0030 {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::Verify,
                        )));
                    }
                    input = remainder;
                }

                let (remainder, _) = le_u32.parse(input)?;
                let (remainder, _) = length_data(le_u32).parse(remainder)?;
                let (remainder, _) = (le_u32, le_u16).parse(remainder)?;
                let (remainder, _) = take(16_usize).parse(remainder)?;
                let (remainder, _) = le_u32.parse(remainder)?;
                input = remainder;
            }
            0x000D => {
                // REFERENCEREGISTERED
                let (remainder, _) = le_u32.parse(input)?;
                let (remainder, _) = length_data(le_u32).parse(remainder)?;
                let (remainder, _) = (
                    verify(le_u32, |&val| val == 0x0000),
                    verify(le_u16, |&val| val == 0x0000),
                )
                    .parse(remainder)?;
                input = remainder;
            }
            0x000E => {
                // REFERENCEPROJECT
                let (remainder, _) = le_u32.parse(input)?;
                let (remainder, _) = length_data(le_u32).parse(remainder)?;
                let (remainder, _) = length_data(le_u32).parse(remainder)?;
                let (remainder, _) = (le_u32, le_u16).parse(remainder)?;
                input = remainder;
            }
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Switch,
                )));
            }
        }
    }
    Ok((input, references))
}

fn parse_modules<'a>(
    mut input: &'a [u8],
    modules_count: u16,
    module_streams: &HashMap<String, Vec<u8>>,
    vba: &mut Vba,
) -> Result<(&'a [u8], ()), nom::Err<Error<'a>>> {
    for _ in 0..modules_count {
        // MODULENAME record
        let (remainder, _) =
            verify(le_u16, |&id| id == 0x0019).parse(input)?;

        let (remainder, module_name) = length_data(le_u32)
            .map(String::from_utf8_lossy)
            .parse(remainder)?;

        input = remainder;

        let mut module_type = ModuleType::MODULE_TYPE_UNKNOWN;
        let mut stream_name = None;
        let mut module_offset = 0u32;

        // Read sections until terminator 0x002B
        loop {
            let (remainder, section_id) = le_u16.parse(input)?;
            input = remainder;
            match section_id {
                0x0047 => {
                    // MODULENAMEUNICODE
                    let (remainder, _) = length_data(le_u32).parse(input)?;
                    input = remainder;
                }
                0x001A => {
                    // MODULESTREAMNAME
                    let (remainder, name) = length_data(le_u32)
                        .map(String::from_utf8_lossy)
                        .parse(input)?;

                    let (remainder, _) = verify(le_u16, |&val| val == 0x0032)
                        .parse(remainder)?;

                    let (remainder, _) =
                        length_data(le_u32).parse(remainder)?;

                    stream_name = Some(name);
                    input = remainder;
                }
                0x001C => {
                    // MODULEDOCSTRING
                    let (remainder, _) = length_data(le_u32).parse(input)?;

                    let (remainder, _) = verify(le_u16, |&val| val == 0x0048)
                        .parse(remainder)?;

                    let (remainder, _) =
                        length_data(le_u32).parse(remainder)?;
                    input = remainder;
                }
                0x0031 => {
                    // MODULEOFFSET
                    let (remainder, _) =
                        verify(le_u32, |&size| size == 0x0004).parse(input)?;
                    let (remainder, offset) = le_u32.parse(remainder)?;
                    module_offset = offset;
                    input = remainder;
                }
                0x001E => {
                    // MODULEHELPCONTEXT
                    let (remainder, _) =
                        verify(le_u32, |&size| size == 0x0004).parse(input)?;
                    let (remainder, _) = le_u32.parse(remainder)?;
                    input = remainder;
                }
                0x002C => {
                    // MODULECOOKIE
                    let (remainder, _) =
                        verify(le_u32, |&size| size == 0x0002).parse(input)?;
                    let (remainder, _) = le_u16.parse(remainder)?;
                    input = remainder;
                }
                0x0021 => {
                    module_type = ModuleType::MODULE_TYPE_STANDARD;
                    let (remainder, _) = le_u32.parse(input)?;
                    input = remainder;
                }
                0x0022 => {
                    module_type = ModuleType::MODULE_TYPE_CLASS;
                    let (remainder, _) = le_u32.parse(input)?;
                    input = remainder;
                }
                0x0025 => {
                    let (remainder, _) =
                        verify(le_u32, |&val| val == 0x0000).parse(input)?;
                    input = remainder;
                }
                0x0028 => {
                    let (remainder, _) =
                        verify(le_u32, |&val| val == 0x0000).parse(input)?;
                    input = remainder;
                }
                0x002B => {
                    // TERMINATOR
                    let (remainder, _) =
                        verify(le_u32, |&val| val == 0x0000).parse(input)?;
                    input = remainder;
                    break;
                }
                _ => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Switch,
                    )));
                }
            }
        }

        // Retrieve module code
        let mut code = None;

        if let Some(stream_name) = stream_name
            && let Some(module_data) = module_streams.get(stream_name.as_ref())
        {
            if module_offset as usize >= module_data.len() {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
            let code_data = &module_data[module_offset as usize..];
            if !code_data.is_empty() {
                code = decompress_stream(code_data)
                    .ok()
                    .and_then(|d| String::from_utf8(d).ok());
            }
        }

        if let Some(code) = code {
            vba.module_names.push(module_name.to_string());
            vba.module_types.push(::protobuf::EnumOrUnknown::new(module_type));
            vba.module_codes.push(code);
        }
    }

    Ok((input, ()))
}
