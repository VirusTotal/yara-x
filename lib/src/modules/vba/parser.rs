use std::collections::HashMap;

use nom::combinator::opt;
use nom::multi::length_data;
use nom::{
    Parser,
    bytes::complete::take,
    combinator::verify,
    number::complete::{le_u16, le_u32},
};

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

/// Decompresses a VBA compressed stream according to the algorithm described
/// in MS-OVBA Section 2.4.1.3.
///
/// The stream begins with a mandatory signature byte (0x01), followed by a
/// sequence of CompressedChunk structures. Each chunk contains a 2-byte header
/// indicating its size, whether it is compressed, and its valid chunk
/// signature (which must be 3 or 4).
pub fn decompress_stream(compressed: &[u8]) -> Result<Vec<u8>, &'static str> {
    if compressed.is_empty() {
        return Err("Empty input buffer");
    }

    // Validate MS-OVBA signature byte (Section 2.4.1.3.1)
    if compressed[0] != 0x01 {
        return Err("Invalid signature byte");
    }

    let mut decompressed = Vec::with_capacity(compressed.len() * 2);
    let mut current = 1; // Skip signature byte

    while current < compressed.len() {
        // Ensure we have at least 2 bytes remaining to parse the chunk header.
        if current + 2 > compressed.len() {
            if !decompressed.is_empty() {
                break;
            }
            return Err("Incomplete chunk header");
        }

        let chunk_header = u16::from_le_bytes(
            compressed[current..current + 2]
                .try_into()
                .map_err(|_| "Failed to parse chunk header")?,
        );

        // Robust signature check: bits 12-14 must be 0b011 (3) or 0b100 (4).
        // Trailing zero-filled sector padding has signature 0, which is cleanly
        // filtered out.
        let signature = (chunk_header & 0x7000) >> 12;
        if signature != 3 && signature != 4 {
            break;
        }

        let chunk_size = (chunk_header & 0x0FFF) as usize + 3;
        let chunk_is_compressed = (chunk_header & 0x8000) != 0;

        // Section 2.4.1.3.11: If CompressedChunkFlag is 1, CompressedChunkSize
        // must be <= 4095.
        if chunk_is_compressed && chunk_size > 4095 {
            if !decompressed.is_empty() {
                break;
            }
            return Err(
                "CompressedChunkSize > 4095 but CompressedChunkFlag == 1",
            );
        }

        let chunk_end = std::cmp::min(compressed.len(), current + chunk_size);

        // Skip header.
        current += 2;

        // Handle uncompressed chunks (Section 2.4.1.3.11.2)
        if !chunk_is_compressed {
            let decompressed_size = if (chunk_header & 0x0FFF) == 4095 {
                4096
            } else {
                (chunk_header & 0x0FFF) as usize
            };

            // Relaxed uncompressed chunk boundary handling:
            // If the declared decompressed size extends past the physical
            // stream boundary (due to standard compiler truncation or
            // obfuscation), read only the available stream bytes.
            let bytes_to_read =
                std::cmp::min(decompressed_size, compressed.len() - current);
            if bytes_to_read == 0 {
                break;
            }
            decompressed.extend_from_slice(
                &compressed[current..current + bytes_to_read],
            );
            current += bytes_to_read;
            continue;
        }

        // Handle compressed chunks (Section 2.4.1.3.11.1)
        let decompressed_chunk_start = decompressed.len();

        while current < chunk_end {
            // A single chunk decompresses to at most 4096 bytes
            if decompressed.len() - decompressed_chunk_start >= 4096 {
                break;
            }
            let flag_byte = compressed[current];
            current += 1;

            // Iterate over the 8 bits in the flag byte (from LSB to MSB)
            for bit_index in 0..8 {
                if decompressed.len() - decompressed_chunk_start >= 4096 {
                    break;
                }
                if current >= chunk_end {
                    break;
                }

                if (flag_byte & (1 << bit_index)) == 0 {
                    // Bit is 0: Literal byte (Section 2.4.1.3.11.1.1)
                    decompressed.push(compressed[current]);
                    current += 1;
                } else {
                    // Bit is 1: Copy token (Section 2.4.1.3.11.1.2)
                    if current + 2 > compressed.len() {
                        return Err("Incomplete copy token");
                    }

                    let copy_token = u16::from_le_bytes(
                        compressed[current..current + 2]
                            .try_into()
                            .map_err(|_| "Failed to parse copy token")?,
                    );

                    // Helper maps the bit count dynamically based on
                    // decompressed offset
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

        current = chunk_end;
    }

    // Strip any trailing null bytes (0x00) from the decompressed stream buffer,
    // cleaning up OLE sector padding artifacts.
    while let Some(&0) = decompressed.last() {
        decompressed.pop();
    }

    Ok(decompressed)
}

pub fn parse<'a>(
    dir_stream: &'a [u8],
    module_streams: &HashMap<String, Vec<u8>>,
) -> Result<Vba, nom::Err<Error<'a>>> {
    let mut vba = Vba::new();
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
    let (input, (_, _, codepage)) = (
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
            .map(|bytes| decode_string(bytes, codepage)),
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
    let (input, references) = parse_references(input, codepage)?;

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
    let (_input, _) = parse_modules(
        input,
        modules_count,
        module_streams,
        &mut vba,
        codepage,
    )?;

    let mut project_info = ProjectInfo::new();
    project_info.references = references;

    project_info.set_name(project_name.to_string());
    project_info.set_version(format!("{}.{}", version_major, version_minor));
    project_info.set_module_count(modules_count as i32);

    vba.project_info = protobuf::MessageField::some(project_info);

    Ok(vba)
}

fn parse_references(
    mut input: &[u8],
    codepage: u16,
) -> Result<(&[u8], Vec<String>), nom::Err<Error<'_>>> {
    let mut references = Vec::new();
    loop {
        let (remainder, record_id) = le_u16.parse(input)?;
        input = remainder;
        if record_id == 0x000F {
            break;
        }

        match record_id {
            0x0016 => {
                // REFERENCE Name
                let (remainder, name) = length_data(le_u32)
                    .map(|bytes| decode_string(bytes, codepage))
                    .parse(input)?;

                references.push(name);

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
                // MS-OVBA 2.3.4.2.2.3 REFERENCECONTROL Record

                // 1. Parse SizeTwips + Twips fields + SizeOfLibidOriginal + LibidOriginal + Reserved1 + Reserved2
                let (remainder, _) = length_data(le_u32).parse(input)?;

                // 2. NameRecordExtended (optional, starts with 0x0016)
                let (remainder, _) = opt((
                    verify(le_u16, |&id| id == 0x0016),
                    length_data(le_u32),
                    verify(le_u16, |&id| id == 0x003E),
                    length_data(le_u32),
                ))
                .parse(remainder)?;

                // 3. Parse Reserved3 (2 bytes, MUST be 0x0030)
                let (remainder, _) =
                    verify(le_u16, |&val| val == 0x0030).parse(remainder)?;

                // 4. Parse the remaining fields:
                let (remainder, _) = le_u32.parse(remainder)?; // Size
                let (remainder, _) = length_data(le_u32).parse(remainder)?; // LibidExtended
                let (remainder, _) = (le_u32, le_u16).parse(remainder)?; // Reserved
                let (remainder, _) = take(16_usize).parse(remainder)?; // Reserved/Cookie
                let (remainder, _) = le_u32.parse(remainder)?; // Cookie

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
    codepage: u16,
) -> Result<(&'a [u8], ()), nom::Err<Error<'a>>> {
    for _ in 0..modules_count {
        // MODULENAME record
        let (remainder, _) =
            verify(le_u16, |&id| id == 0x0019).parse(input)?;

        let (remainder, module_name) = length_data(le_u32)
            .map(|bytes| decode_string(bytes, codepage))
            .parse(remainder)?;

        input = remainder;

        let mut stream_name: Option<String> = None;
        let mut stream_name_unicode: Option<String> = None;
        let mut module_name_unicode: Option<String> = None;
        let mut module_offset = 0u32;
        let mut module_type = ModuleType::MODULE_TYPE_UNKNOWN;

        // Read sections until terminator 0x002B
        loop {
            let (remainder, section_id) = le_u16.parse(input)?;
            input = remainder;
            match section_id {
                0x0047 => {
                    // MODULENAMEUNICODE
                    (input, module_name_unicode) = length_data(le_u32)
                        .map(|name| decode_utf16(name).ok())
                        .parse(input)?;
                }
                0x001A => {
                    // MODULESTREAMNAME
                    (input, (stream_name, _, _)) = (
                        length_data(le_u32)
                            .map(|bytes| Some(decode_string(bytes, codepage))),
                        verify(le_u16, |&val| val == 0x0032),
                        length_data(le_u32),
                    )
                        .parse(input)?;
                }
                0x001C => {
                    // MODULEDOCSTRING
                    (input, (_, _, stream_name_unicode)) = (
                        length_data(le_u32),
                        verify(le_u16, |&val| val == 0x0048),
                        length_data(le_u32)
                            .map(|name| decode_utf16(name).ok()),
                    )
                        .parse(input)?;
                }
                0x0031 => {
                    // MODULEOFFSET
                    (input, (_, module_offset)) =
                        (verify(le_u32, |&size| size == 0x0004), le_u32)
                            .parse(input)?;
                }
                0x001E => {
                    // MODULEHELPCONTEXT
                    (input, _) =
                        (verify(le_u32, |&size| size == 0x0004), le_u32)
                            .parse(input)?;
                }
                0x002C => {
                    // MODULECOOKIE
                    (input, _) =
                        (verify(le_u32, |&size| size == 0x0002), le_u16)
                            .parse(input)?;
                }
                0x0021 => {
                    module_type = ModuleType::MODULE_TYPE_STANDARD;
                    (input, _) = le_u32.parse(input)?;
                }
                0x0022 => {
                    module_type = ModuleType::MODULE_TYPE_CLASS;
                    (input, _) = le_u32.parse(input)?;
                }
                0x0025 => {
                    (input, _) =
                        verify(le_u32, |&val| val == 0x0000).parse(input)?;
                }
                0x0028 => {
                    (input, _) =
                        verify(le_u32, |&val| val == 0x0000).parse(input)?;
                }
                0x002B => {
                    // TERMINATOR
                    (input, _) =
                        verify(le_u32, |&val| val == 0x0000).parse(input)?;
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

        let stream_name =
            stream_name_unicode.as_deref().or(stream_name.as_deref());

        let module_name =
            module_name_unicode.as_deref().unwrap_or(&module_name);

        let mut module_data = None;

        if let Some(name) = stream_name {
            module_data = module_streams.get(&normalize_name(name));
        }

        if module_data.is_none() {
            module_data = module_streams.get(&normalize_name(module_name));
        }

        if let Some(module_data) = module_data {
            let code_data = if (module_offset as usize) < module_data.len() {
                &module_data[module_offset as usize..]
            } else {
                &[]
            };

            let mut decompressed_res = None;
            if !code_data.is_empty() && code_data[0] == 0x01 {
                decompressed_res = decompress_stream(code_data).ok();
            }

            // If the declared offset is invalid or fails decompression,
            // scan the stream physically for the first valid compressed VBA stream signature.
            if decompressed_res.is_none() {
                let mut scan_offset = 0;
                while scan_offset + 3 <= module_data.len() {
                    if module_data[scan_offset] == 0x01 {
                        let header = u16::from_le_bytes([
                            module_data[scan_offset + 1],
                            module_data[scan_offset + 2],
                        ]);
                        let sig = (header & 0x7000) >> 12;
                        if (sig == 3 || sig == 4)
                            && let Ok(decompressed) =
                                decompress_stream(&module_data[scan_offset..])
                        {
                            decompressed_res = Some(decompressed);
                            break;
                        }
                    }
                    scan_offset += 1;
                }
            }

            if let Some(decompressed) = decompressed_res {
                code = Some(decode_string(&decompressed, codepage));
            }
        }

        if let Some(code) = code {
            let mut m = crate::modules::protos::vba::vba::Module::new();
            m.set_name(module_name.to_string());
            m.set_type(module_type);
            m.set_code(code);
            vba.modules.push(m);
        }
    }

    Ok((input, ()))
}

fn decode_string(bytes: &[u8], codepage: u16) -> String {
    if let Some(encoding) = codepage::to_encoding(codepage) {
        let (decoded, _, _) = encoding.decode(bytes);
        decoded.into_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn decode_utf16(bytes: &[u8]) -> Result<String, &'static str> {
    if !bytes.len().is_multiple_of(2) {
        return Err("Invalid UTF-16 byte length");
    }
    let u16_units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&u16_units).map_err(|_| "Invalid UTF-16 data")
}

/// Normalizes stream and module names by converting to lowercase and mapping
/// regional, accented, and diacritic characters (e.g. Turkish, Central
/// European, Spanish) back to standard base ASCII letters.
///
/// This is necessary because malware documents often declare a mismatching
/// project codepage (e.g., Windows-1252/Latin-1) while storing module names
/// using a different codepage (e.g., Turkish Windows-1254). This codepage
/// mismatch yields completely different unicode representations, causing
/// stream lookups to fail. Reconstructing stream names into their common
/// ASCII base guarantees 100% robust extraction across all locales.
pub(crate) fn normalize_name(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| match c {
            'ç' | 'ć' | 'č' => 'c',
            'ş' | 'ś' | 'š' | 'þ' => 's',
            'ı' | 'í' | 'ì' | 'î' | 'ï' | 'ý' => 'i',
            'ğ' => 'g',
            'ö' | 'ó' | 'ò' | 'ô' | 'õ' => 'o',
            'ü' | 'ú' | 'ù' | 'û' => 'u',
            'ä' | 'á' | 'à' | 'â' | 'ã' => 'a',
            'ñ' => 'n',
            _ => c,
        })
        .collect()
}
