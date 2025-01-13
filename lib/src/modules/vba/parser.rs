use std::collections::HashMap;
use nom::{
    number::complete::{le_u16, le_u32},
};

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

    pub fn decompress_stream(compressed: &[u8]) -> Result<Vec<u8>, &'static str> {
        if compressed.is_empty() {
            return Err("Empty input buffer");
        }
    
        if compressed[0] != 0x01 {
            return Err("Invalid signature byte");
        }
    
        let mut decompressed = Vec::new();
        let mut current = 1; // Skip signature byte
    
        while current < compressed.len() {
            // We need 2 bytes for the chunk header
            if current + 2 > compressed.len() {
                return Err("Incomplete chunk header");
            }
    
            let chunk_header = u16::from_le_bytes(
                compressed[current..current+2].try_into().map_err(|_| "Failed to parse chunk header")?
            );
            let chunk_size = (chunk_header & 0x0FFF) as usize + 3;
            let chunk_is_compressed = (chunk_header & 0x8000) != 0;
            
            current += 2;
    
            if chunk_is_compressed && chunk_size > 4095 {
                return Err("CompressedChunkSize > 4095 but CompressedChunkFlag == 1");
            }
            if !chunk_is_compressed && chunk_size != 4095 {
                return Err("CompressedChunkSize != 4095 but CompressedChunkFlag == 0");
            }
    
            let chunk_end = std::cmp::min(compressed.len(), current + chunk_size);
    
            if !chunk_is_compressed {
                if current + 4096 > compressed.len() {
                    return Err("Incomplete uncompressed chunk");
                }
                decompressed.extend_from_slice(&compressed[current..current + 4096]);
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
                            compressed[current..current+2].try_into().map_err(|_| "Failed to parse copy token")?
                        );
                        let (length_mask, offset_mask, bit_count, _) =
                            Self::copytoken_help(decompressed.len() - decompressed_chunk_start);
    
                        let length = (copy_token & length_mask) + 3;
                        let temp1 = copy_token & offset_mask;
                        let temp2 = 16 - bit_count;
                        let offset = u16::try_from((temp1 >> temp2) + 1)
                            .map_err(|_| "Offset calculation overflow")?;
    
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

    fn parse_u16(input: &[u8]) -> Result<(&[u8], u16), &'static str> {
        le_u16::<&[u8], nom::error::Error<&[u8]>>(input)
            .map_err(|_nom_err| "Failed to parse u16")
    }

    fn parse_u32(input: &[u8]) -> Result<(&[u8], u32), &'static str> {
        le_u32::<&[u8], nom::error::Error<&[u8]>>(input)
            .map_err(|_nom_err| "Failed to parse u32")
    }

    fn parse_bytes<'a>(input: &'a [u8], len: usize) -> Result<(&'a [u8], &'a [u8]), &'static str> {
        if input.len() < len {
            Err("Not enough bytes to parse the requested slice")
        } else {
            Ok((&input[len..], &input[..len]))
        }
    }

    pub fn parse(compressed_dir_stream: &[u8], module_streams: HashMap<String, Vec<u8>>) -> Result<Self, &'static str> {
        let dir_stream = Self::decompress_stream(compressed_dir_stream)?;

        // Our 'input' will move forward as we parse
        let mut _input = &dir_stream[..];

        // -- PROJECTSYSKIND Record
        let (rest, syskind_id) = Self::parse_u16(_input)?;  _input = rest;
        if syskind_id != 0x0001 {
            return Err("Invalid SYSKIND_ID");
        }
        let (rest, syskind_size) = Self::parse_u32(_input)?; _input = rest;
        if syskind_size != 0x0004 {
            return Err("Invalid SYSKIND_SIZE");
        }
        let (rest, _syskind) = Self::parse_u32(_input)?; _input = rest;

        // -- PROJECTLCID Record
        let (rest, lcid_id) = Self::parse_u16(_input)?; _input = rest;
        if lcid_id != 0x0002 {
            return Err("Invalid LCID_ID");
        }
        let (rest, lcid_size) = Self::parse_u32(_input)?; _input = rest;
        if lcid_size != 0x0004 {
            return Err("Invalid LCID_SIZE");
        }
        let (rest, lcid) = Self::parse_u32(_input)?; _input = rest;
        if lcid != 0x409 {
            return Err("Invalid LCID");
        }

        // -- PROJECTLCIDINVOKE Record
        let (rest, lcid_invoke_id) = Self::parse_u16(_input)?; _input = rest;
        if lcid_invoke_id != 0x0014 {
            return Err("Invalid LCIDINVOKE_ID");
        }
        let (rest, lcid_invoke_size) = Self::parse_u32(_input)?; _input = rest;
        if lcid_invoke_size != 0x0004 {
            return Err("Invalid LCIDINVOKE_SIZE");
        }
        let (rest, lcid_invoke) = Self::parse_u32(_input)?; _input = rest;
        if lcid_invoke != 0x409 {
            return Err("Invalid LCIDINVOKE");
        }

        // -- PROJECTCODEPAGE Record
        let (rest, codepage_id) = Self::parse_u16(_input)?; _input = rest;
        if codepage_id != 0x0003 {
            return Err("Invalid CODEPAGE_ID");
        }
        let (rest, codepage_size) = Self::parse_u32(_input)?; _input = rest;
        if codepage_size != 0x0002 {
            return Err("Invalid CODEPAGE_SIZE");
        }
        let (rest, _codepage) = Self::parse_u16(_input)?; _input = rest;

        // -- PROJECTNAME Record
        let (rest, name_id) = Self::parse_u16(_input)?; _input = rest;
        if name_id != 0x0004 {
            return Err("Invalid NAME_ID");
        }
        let (rest, name_size) = Self::parse_u32(_input)?; _input = rest;
        let name_size = name_size as usize;
        if name_size < 1 || name_size > 128 {
            return Err("Project name not in valid range");
        }
        let (rest, name_bytes) = Self::parse_bytes(rest, name_size)?; 
        let project_name = String::from_utf8_lossy(name_bytes).to_string();
        _input = rest;

        // -- PROJECTDOCSTRING Record
        let (rest, doc_id) = Self::parse_u16(_input)?; _input = rest;
        if doc_id != 0x0005 {
            return Err("Invalid DOCSTRING_ID");
        }
        let (rest, doc_size) = Self::parse_u32(_input)?; _input = rest;
        let doc_size = doc_size as usize;
        let (rest, _doc_string) = Self::parse_bytes(rest, doc_size)?; 
        _input = rest;
        let (rest, doc_reserved) = Self::parse_u16(_input)?; _input = rest;
        if doc_reserved != 0x0040 {
            return Err("Invalid DOCSTRING_Reserved");
        }
        let (rest, doc_unicode_size) = Self::parse_u32(_input)?; _input = rest;
        let doc_unicode_size = doc_unicode_size as usize;
        if doc_unicode_size % 2 != 0 {
            return Err("DOCSTRING_Unicode size not even");
        }
        let (rest, _doc_unicode) = Self::parse_bytes(rest, doc_unicode_size)?;
        _input = rest;

        // -- PROJECTHELPFILEPATH Record
        let (rest, helpfile_id) = Self::parse_u16(_input)?; _input = rest;
        if helpfile_id != 0x0006 {
            return Err("Invalid HELPFILEPATH_ID");
        }
        let (rest, helpfile_size1) = Self::parse_u32(_input)?; _input = rest;
        let helpfile_size1 = helpfile_size1 as usize;
        if helpfile_size1 > 260 {
            return Err("Help file path 1 too long");
        }
        let (rest, helpfile1) = Self::parse_bytes(rest, helpfile_size1)?; 
        _input = rest;
        let (rest, helpfile_reserved) = Self::parse_u16(_input)?; _input = rest;
        if helpfile_reserved != 0x003D {
            return Err("Invalid HELPFILEPATH_Reserved");
        }
        let (rest, helpfile_size2) = Self::parse_u32(_input)?; _input = rest;
        let helpfile_size2 = helpfile_size2 as usize;
        if helpfile_size2 != helpfile_size1 {
            return Err("Help file sizes don't match");
        }
        let (rest, helpfile2) = Self::parse_bytes(rest, helpfile_size2)?; 
        _input = rest;
        if helpfile1 != helpfile2 {
            return Err("Help files don't match");
        }

        // -- PROJECTHELPCONTEXT Record
        let (rest, helpcontext_id) = Self::parse_u16(_input)?; _input = rest;
        if helpcontext_id != 0x0007 {
            return Err("Invalid HELPCONTEXT_ID");
        }
        let (rest, helpcontext_size) = Self::parse_u32(_input)?; _input = rest;
        if helpcontext_size != 0x0004 {
            return Err("Invalid HELPCONTEXT_SIZE");
        }
        let (rest, _helpcontext) = Self::parse_u32(_input)?; _input = rest;

        // -- PROJECTLIBFLAGS Record
        let (rest, libflags_id) = Self::parse_u16(_input)?; _input = rest;
        if libflags_id != 0x0008 {
            return Err("Invalid LIBFLAGS_ID");
        }
        let (rest, libflags_size) = Self::parse_u32(_input)?; _input = rest;
        if libflags_size != 0x0004 {
            return Err("Invalid LIBFLAGS_SIZE");
        }
        let (rest, libflags) = Self::parse_u32(_input)?; _input = rest;
        if libflags != 0x0000 {
            return Err("Invalid LIBFLAGS");
        }

        // -- PROJECTVERSION Record
        let (rest, version_id) = Self::parse_u16(_input)?; _input = rest;
        if version_id != 0x0009 {
            return Err("Invalid VERSION_ID");
        }
        let (rest, version_reserved) = Self::parse_u32(_input)?; _input = rest;
        if version_reserved != 0x0004 {
            return Err("Invalid VERSION_Reserved");
        }
        let (rest, version_major) = Self::parse_u32(_input)?; _input = rest;
        let (rest, version_minor) = Self::parse_u16(_input)?; _input = rest;

        // -- PROJECTCONSTANTS Record
        let (rest, constants_id) = Self::parse_u16(_input)?; _input = rest;
        if constants_id != 0x000C {
            return Err("Invalid CONSTANTS_ID");
        }
        let (rest, constants_size) = Self::parse_u32(_input)?; _input = rest;
        let constants_size = constants_size as usize;
        if constants_size > 1015 {
            return Err("Constants size too large");
        }
        let (rest, _constants) = Self::parse_bytes(rest, constants_size)?; 
        _input = rest;
        let (rest, constants_reserved) = Self::parse_u16(_input)?; _input = rest;
        if constants_reserved != 0x003C {
            return Err("Invalid CONSTANTS_Reserved");
        }
        let (rest, constants_unicode_size) = Self::parse_u32(_input)?; _input = rest;
        let constants_unicode_size = constants_unicode_size as usize;
        if constants_unicode_size % 2 != 0 {
            return Err("Constants unicode size not even");
        }
        let (rest, _constants_unicode) = Self::parse_bytes(rest, constants_unicode_size)?;
        _input = rest;

        // -- Parse references until we hit PROJECTMODULES_Id = 0x000F
        let mut references = Vec::new();
        let mut last_check;
        loop {
            let (rest2, check) = match Self::parse_u16(_input) {
                Ok(x) => x,
                Err(_) => return Err("Could not parse reference type (u16)"),
            };
            _input = rest2;
            last_check = check;

            if check == 0x000F {
                // That means we reached PROJECTMODULES_Id
                break;
            }

            match check {
                0x0016 => {
                    // REFERENCE Name
                    let (rest2, name_size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, name_bytes) = Self::parse_bytes(_input, name_size as usize)?; 
                    _input = rest2;
                    let name = String::from_utf8_lossy(name_bytes).to_string();
                    references.push(name);

                    let (rest2, reserved) = Self::parse_u16(_input)?; _input = rest2;
                    if reserved != 0x003E {
                        return Err("Invalid REFERENCE_Reserved");
                    }
                    let (rest2, unicode_size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _name_unicode) = Self::parse_bytes(_input, unicode_size as usize)?;
                    _input = rest2;
                },
                0x0033 => {
                    // REFERENCEORIGINAL
                    let (rest2, size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _libid) = Self::parse_bytes(_input, size as usize)?;
                    _input = rest2;
                },
                0x002F => {
                    // REFERENCECONTROL
                    let (rest2, size_twiddled) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _twiddled) = Self::parse_bytes(_input, size_twiddled as usize)?;
                    _input = rest2;
                    
                    let (rest2, reserved1) = Self::parse_u32(_input)?; _input = rest2;
                    if reserved1 != 0x0000 {
                        return Err("Invalid REFERENCECONTROL_Reserved1");
                    }
                    let (rest2, reserved2) = Self::parse_u16(_input)?; _input = rest2;
                    if reserved2 != 0x0000 {
                        return Err("Invalid REFERENCECONTROL_Reserved2");
                    }

                    // Possibly an optional name record
                    let (maybe_rest, maybe_check2) = match Self::parse_u16(_input) {
                        Ok(x) => x,
                        Err(_) => return Err("Failed to read optional name or reserved3"),
                    };
                    
                    if maybe_check2 == 0x0016 {
                        // This means we have a name record
                        _input = maybe_rest;
                        let (rest2, name_size) = Self::parse_u32(_input)?; _input = rest2;
                        let (rest2, _name) = Self::parse_bytes(_input, name_size as usize)?; 
                        _input = rest2;
                        
                        let (rest2, reserved) = Self::parse_u16(_input)?; _input = rest2;
                        if reserved != 0x003E {
                            return Err("Invalid REFERENCECONTROL_NameRecord_Reserved");
                        }
                        let (rest2, unicode_size) = Self::parse_u32(_input)?; _input = rest2;
                        let (rest2, _name_unicode) = Self::parse_bytes(_input, unicode_size as usize)?;
                        _input = rest2;

                        // Next we parse the next 0x0030
                        let (rest2, reserved3) = Self::parse_u16(_input)?; _input = rest2;
                        if reserved3 != 0x0030 {
                            return Err("Invalid REFERENCECONTROL_Reserved3");
                        }
                    } else {
                        // No name record, so maybe_check2 is actually reserved3
                        _input = maybe_rest;
                        if maybe_check2 != 0x0030 {
                            return Err("Invalid REFERENCECONTROL_Reserved3");
                        }
                    }

                    let (rest2, size_extended) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, size_libid) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _libid) = Self::parse_bytes(_input, size_libid as usize)?;
                    _input = rest2;
                    let (rest2, _reserved4) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _reserved5) = Self::parse_u16(_input)?; _input = rest2;
                    let (rest2, _original_typelib) = Self::parse_bytes(_input, 16)?;
                    _input = rest2;
                    let (rest2, _cookie) = Self::parse_u32(_input)?; _input = rest2;
                    let _ = size_extended; // just to avoid unused var warnings
                },
                0x000D => {
                    // REFERENCEREGISTERED
                    let (rest2, _size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, libid_size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _libid) = Self::parse_bytes(_input, libid_size as usize)?;
                    _input = rest2;
                    let (rest2, reserved1) = Self::parse_u32(_input)?; _input = rest2;
                    if reserved1 != 0x0000 {
                        return Err("Invalid REFERENCEREGISTERED_Reserved1");
                    }
                    let (rest2, reserved2) = Self::parse_u16(_input)?; _input = rest2;
                    if reserved2 != 0x0000 {
                        return Err("Invalid REFERENCEREGISTERED_Reserved2");
                    }
                },
                0x000E => {
                    // REFERENCEPROJECT
                    let (rest2, _size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, libid_abs_size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _libid_abs) = Self::parse_bytes(_input, libid_abs_size as usize)?;
                    _input = rest2;
                    let (rest2, libid_rel_size) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _libid_rel) = Self::parse_bytes(_input, libid_rel_size as usize)?;
                    _input = rest2;
                    let (rest2, _major) = Self::parse_u32(_input)?; _input = rest2;
                    let (rest2, _minor) = Self::parse_u16(_input)?; _input = rest2;
                },
                _ => return Err("Invalid reference type"),
            }
        }

        if last_check != 0x000F {
            return Err("Invalid PROJECTMODULES_Id");
        }
        
        let (rest, modules_size) = Self::parse_u32(_input)?; _input = rest;
        if modules_size != 0x0002 {
            return Err("Invalid PROJECTMODULES_Size");
        }
        
        let (rest, modules_count) = Self::parse_u16(_input)?; _input = rest;

        let (rest, cookie_id) = Self::parse_u16(_input)?; _input = rest;
        if cookie_id != 0x0013 {
            return Err("Invalid ProjectCookie_Id");
        }
        
        let (rest, cookie_size) = Self::parse_u32(_input)?; _input = rest;
        if cookie_size != 0x0002 {
            return Err("Invalid ProjectCookie_Size");
        }
        
        let (rest, _cookie) = Self::parse_u16(_input)?; 
        _input = rest;

        // -- Parse each module
        let mut modules = HashMap::new();
        for _ in 0..modules_count {
            // MODULENAME record
            let (rest2, module_id) = Self::parse_u16(_input)?; 
            _input = rest2;
            if module_id != 0x0019 {
                return Err("Invalid MODULENAME_Id");
            }
            
            let (rest2, module_name_size) = Self::parse_u32(_input)?; 
            _input = rest2;
            let (rest2, name_bytes) = Self::parse_bytes(_input, module_name_size as usize)?; 
            _input = rest2;
            let module_name = String::from_utf8_lossy(name_bytes).to_string();

            let mut module_type = ModuleType::Unknown;
            let mut stream_name = String::new();
            let mut module_offset = 0u32;

            // Read all sections until we get the terminator 0x002B
            loop {
                let (rest2, section_id) = match Self::parse_u16(_input) {
                    Ok(x) => x,
                    Err(_) => return Err("Failed to parse module section ID"),
                };
                _input = rest2;

                match section_id {
                    0x0047 => {
                        // MODULENAMEUNICODE
                        let (rest3, unicode_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        let (rest3, _unicode_name) = Self::parse_bytes(_input, unicode_size as usize)?;
                        _input = rest3;
                    },
                    0x001A => {
                        // MODULESTREAMNAME
                        let (rest3, stream_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        let (rest3, stream_bytes) = Self::parse_bytes(_input, stream_size as usize)?;
                        _input = rest3;
                        stream_name = String::from_utf8_lossy(stream_bytes).to_string();
                        
                        let (rest3, reserved) = Self::parse_u16(_input)?; 
                        _input = rest3;
                        if reserved != 0x0032 {
                            return Err("Invalid STREAMNAME_Reserved");
                        }
                        
                        let (rest3, unicode_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        let (rest3, _unicode_name) = Self::parse_bytes(_input, unicode_size as usize)?;
                        _input = rest3;
                    },
                    0x001C => {
                        // MODULEDOCSTRING
                        let (rest3, doc_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        let (rest3, _doc_string) = Self::parse_bytes(_input, doc_size as usize)?;
                        _input = rest3;
                        
                        let (rest3, reserved) = Self::parse_u16(_input)?; 
                        _input = rest3;
                        if reserved != 0x0048 {
                            return Err("Invalid DOCSTRING_Reserved");
                        }
                        
                        let (rest3, unicode_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        let (rest3, _unicode_doc) = Self::parse_bytes(_input, unicode_size as usize)?;
                        _input = rest3;
                    },
                    0x0031 => {
                        // MODULEOFFSET
                        let (rest3, offset_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        if offset_size != 0x0004 {
                            return Err("Invalid OFFSET_Size");
                        }
                        let (rest3, offset) = Self::parse_u32(_input)?; 
                        module_offset = offset;
                        _input = rest3;
                    },
                    0x001E => {
                        // MODULEHELPCONTEXT
                        let (rest3, help_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        if help_size != 0x0004 {
                            return Err("Invalid HELPCONTEXT_Size");
                        }
                        let (rest3, _help_context) = Self::parse_u32(_input)?; 
                        _input = rest3;
                    },
                    0x002C => {
                        // MODULECOOKIE
                        let (rest3, cookie_size) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        if cookie_size != 0x0002 {
                            return Err("Invalid COOKIE_Size");
                        }
                        let (rest3, _cookie) = Self::parse_u16(_input)?; 
                        _input = rest3;
                    },
                    0x0021 => {
                        // Module is Standard
                        module_type = ModuleType::Standard;
                        let (rest3, _reserved) = Self::parse_u32(_input)?; 
                        _input = rest3;
                    },
                    0x0022 => {
                        // Module is Class
                        module_type = ModuleType::Class;
                        let (rest3, _reserved) = Self::parse_u32(_input)?; 
                        _input = rest3;
                    },
                    0x0025 => {
                        // MODULEREADONLY
                        let (rest3, reserved) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        if reserved != 0x0000 {
                            return Err("Invalid READONLY_Reserved");
                        }
                    },
                    0x0028 => {
                        // MODULEPRIVATE
                        let (rest3, reserved) = Self::parse_u32(_input)?; 
                        _input = rest3;
                        if reserved != 0x0000 {
                            return Err("Invalid PRIVATE_Reserved");
                        }
                    },
                    0x002B => {
                        // TERMINATOR
                        let (rest3, reserved) = Self::parse_u32(_input)?; 
                        if reserved != 0x0000 {
                            return Err("Invalid MODULE_Reserved");
                        }
                        _input = rest3;
                        break;
                    },
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
                    let decompressed = Self::decompress_stream(code_data)?;
                    let code = String::from_utf8_lossy(&decompressed).to_string();
                    modules.insert(
                        module_name.clone(), 
                        VbaModule {
                            name: module_name,
                            code,
                            module_type,
                        }
                    );
                }
            }
        }

        Ok(VbaProject {
            modules,
            info: ProjectInfo {
                name: project_name,
                version: format!("{}.{}", version_major, version_minor),
                references,
            },
        })
    }
}