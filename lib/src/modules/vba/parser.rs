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
            // Ensure we have enough bytes for the chunk header
            if current + 2 > compressed.len() {
                return Err("Incomplete chunk header");
            }
    
            // Read chunk header
            let chunk_header = u16::from_le_bytes([compressed[current], compressed[current + 1]]);
            let chunk_size = (chunk_header & 0x0FFF) as usize + 3;
            let chunk_is_compressed = (chunk_header & 0x8000) != 0;
            
            current += 2;
    
            // Validate chunk size
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
                // Read flag byte
                let flag_byte = compressed[current];
                current += 1;
    
                // Process each bit in the flag byte
                for bit_index in 0..8 {
                    if current >= chunk_end {
                        break;
                    }
    
                    if (flag_byte & (1 << bit_index)) == 0 {
                        // Literal token
                        decompressed.push(compressed[current]);
                        current += 1;
                    } else {
                        // Copy token
                        if current + 2 > compressed.len() {
                            return Err("Incomplete copy token");
                        }
    
                        let copy_token = u16::from_le_bytes([compressed[current], compressed[current + 1]]);
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

    
    pub fn parse(compressed_dir_stream: &[u8], module_streams: HashMap<String, Vec<u8>>) -> Result<Self, &'static str> {
        let dir_stream = Self::decompress_stream(compressed_dir_stream)?;

        let mut pos = 0;
        let mut modules = HashMap::new();
        let mut references = Vec::new();
        let project_name;
        let version_major;
        let version_minor;

        // Parse PROJECTSYSKIND Record
        let syskind_id = read_u16(&dir_stream, &mut pos)?;
        if syskind_id != 0x0001 {
            return Err("Invalid SYSKIND_ID");
        }
        let syskind_size = read_u32(&dir_stream, &mut pos)?;
        if syskind_size != 0x0004 {
            return Err("Invalid SYSKIND_SIZE");
        }
        let _syskind = read_u32(&dir_stream, &mut pos)?;

        // Parse PROJECTLCID Record
        let lcid_id = read_u16(&dir_stream, &mut pos)?;
        if lcid_id != 0x0002 {
            return Err("Invalid LCID_ID");
        }
        let lcid_size = read_u32(&dir_stream, &mut pos)?;
        if lcid_size != 0x0004 {
            return Err("Invalid LCID_SIZE");
        }
        let lcid = read_u32(&dir_stream, &mut pos)?;
        if lcid != 0x409 {
            return Err("Invalid LCID");
        }

        // Parse PROJECTLCIDINVOKE Record
        let lcid_invoke_id = read_u16(&dir_stream, &mut pos)?;
        if lcid_invoke_id != 0x0014 {
            return Err("Invalid LCIDINVOKE_ID");
        }
        let lcid_invoke_size = read_u32(&dir_stream, &mut pos)?;
        if lcid_invoke_size != 0x0004 {
            return Err("Invalid LCIDINVOKE_SIZE");
        }
        let lcid_invoke = read_u32(&dir_stream, &mut pos)?;
        if lcid_invoke != 0x409 {
            return Err("Invalid LCIDINVOKE");
        }

        // Parse PROJECTCODEPAGE Record
        let codepage_id = read_u16(&dir_stream, &mut pos)?;
        if codepage_id != 0x0003 {
            return Err("Invalid CODEPAGE_ID");
        }
        let codepage_size = read_u32(&dir_stream, &mut pos)?;
        if codepage_size != 0x0002 {
            return Err("Invalid CODEPAGE_SIZE");
        }
        let _codepage = read_u16(&dir_stream, &mut pos)?;

        // Parse PROJECTNAME Record
        let name_id = read_u16(&dir_stream, &mut pos)?;
        if name_id != 0x0004 {
            return Err("Invalid NAME_ID");
        }
        let name_size = read_u32(&dir_stream, &mut pos)? as usize;
        if name_size < 1 || name_size > 128 {
            return Err("Project name not in valid range");
        }
        let name_bytes = read_bytes(&dir_stream, &mut pos, name_size)?;
        project_name = String::from_utf8_lossy(&name_bytes).to_string();

        // Parse PROJECTDOCSTRING Record
        let doc_id = read_u16(&dir_stream, &mut pos)?;
        if doc_id != 0x0005 {
            return Err("Invalid DOCSTRING_ID");
        }
        let doc_size = read_u32(&dir_stream, &mut pos)? as usize;
        let _doc_string = read_bytes(&dir_stream, &mut pos, doc_size)?;
        let doc_reserved = read_u16(&dir_stream, &mut pos)?;
        if doc_reserved != 0x0040 {
            return Err("Invalid DOCSTRING_Reserved");
        }
        let doc_unicode_size = read_u32(&dir_stream, &mut pos)? as usize;
        if doc_unicode_size % 2 != 0 {
            return Err("DOCSTRING_Unicode size not even");
        }
        let _doc_unicode = read_bytes(&dir_stream, &mut pos, doc_unicode_size)?;

        // Parse PROJECTHELPFILEPATH Record
        let helpfile_id = read_u16(&dir_stream, &mut pos)?;
        if helpfile_id != 0x0006 {
            return Err("Invalid HELPFILEPATH_ID");
        }
        let helpfile_size1 = read_u32(&dir_stream, &mut pos)? as usize;
        if helpfile_size1 > 260 {
            return Err("Help file path 1 too long");
        }
        let helpfile1 = read_bytes(&dir_stream, &mut pos, helpfile_size1)?;
        let helpfile_reserved = read_u16(&dir_stream, &mut pos)?;
        if helpfile_reserved != 0x003D {
            return Err("Invalid HELPFILEPATH_Reserved");
        }
        let helpfile_size2 = read_u32(&dir_stream, &mut pos)? as usize;
        if helpfile_size2 != helpfile_size1 {
            return Err("Help file sizes don't match");
        }
        let helpfile2 = read_bytes(&dir_stream, &mut pos, helpfile_size2)?;
        if helpfile1 != helpfile2 {
            return Err("Help files don't match");
        }

        // Parse PROJECTHELPCONTEXT Record
        let helpcontext_id = read_u16(&dir_stream, &mut pos)?;
        if helpcontext_id != 0x0007 {
            return Err("Invalid HELPCONTEXT_ID");
        }
        let helpcontext_size = read_u32(&dir_stream, &mut pos)?;
        if helpcontext_size != 0x0004 {
            return Err("Invalid HELPCONTEXT_SIZE");
        }
        let _helpcontext = read_u32(&dir_stream, &mut pos)?;

        // Parse PROJECTLIBFLAGS Record
        let libflags_id = read_u16(&dir_stream, &mut pos)?;
        if libflags_id != 0x0008 {
            return Err("Invalid LIBFLAGS_ID");
        }
        let libflags_size = read_u32(&dir_stream, &mut pos)?;
        if libflags_size != 0x0004 {
            return Err("Invalid LIBFLAGS_SIZE");
        }
        let libflags = read_u32(&dir_stream, &mut pos)?;
        if libflags != 0x0000 {
            return Err("Invalid LIBFLAGS");
        }

        // Parse PROJECTVERSION Record
        let version_id = read_u16(&dir_stream, &mut pos)?;
        if version_id != 0x0009 {
            return Err("Invalid VERSION_ID");
        }
        let version_reserved = read_u32(&dir_stream, &mut pos)?;
        if version_reserved != 0x0004 {
            return Err("Invalid VERSION_Reserved");
        }
        version_major = read_u32(&dir_stream, &mut pos)?;
        version_minor = read_u16(&dir_stream, &mut pos)?;

        // Parse PROJECTCONSTANTS Record
        let constants_id = read_u16(&dir_stream, &mut pos)?;
        if constants_id != 0x000C {
            return Err("Invalid CONSTANTS_ID");
        }
        let constants_size = read_u32(&dir_stream, &mut pos)? as usize;
        if constants_size > 1015 {
            return Err("Constants size too large");
        }
        let _constants = read_bytes(&dir_stream, &mut pos, constants_size)?;
        let constants_reserved = read_u16(&dir_stream, &mut pos)?;
        if constants_reserved != 0x003C {
            return Err("Invalid CONSTANTS_Reserved");
        }
        let constants_unicode_size = read_u32(&dir_stream, &mut pos)? as usize;
        if constants_unicode_size % 2 != 0 {
            return Err("Constants unicode size not even");
        }
        let _constants_unicode = read_bytes(&dir_stream, &mut pos, constants_unicode_size)?;

        // Parse References
        let mut last_check;
        loop {
            let check = read_u16(&dir_stream, &mut pos)?;
            last_check = check;  // Save the check value
            if check == 0x000F {
                break;
            }

            match check {
                0x0016 => {
                    // REFERENCENAME
                    let name_size = read_u32(&dir_stream, &mut pos)? as usize;
                    let name_bytes = read_bytes(&dir_stream, &mut pos, name_size)?;
                    let name = String::from_utf8_lossy(&name_bytes).to_string();
                    references.push(name);

                    let reserved = read_u16(&dir_stream, &mut pos)?;
                    if reserved != 0x003E {
                        return Err("Invalid REFERENCE_Reserved");
                    }
                    let unicode_size = read_u32(&dir_stream, &mut pos)? as usize;
                    let _name_unicode = read_bytes(&dir_stream, &mut pos, unicode_size)?;
                },
                0x0033 => {
                    // REFERENCEORIGINAL
                    let _size = read_u32(&dir_stream, &mut pos)? as usize;
                    let _libid = read_bytes(&dir_stream, &mut pos, _size)?;
                },
                0x002F => {
                    // REFERENCECONTROL
                    let size_twiddled = read_u32(&dir_stream, &mut pos)? as usize;
                    let _twiddled = read_bytes(&dir_stream, &mut pos, size_twiddled)?;
                    
                    let reserved1 = read_u32(&dir_stream, &mut pos)?;
                    if reserved1 != 0x0000 {
                        return Err("Invalid REFERENCECONTROL_Reserved1");
                    }
                    
                    let reserved2 = read_u16(&dir_stream, &mut pos)?;
                    if reserved2 != 0x0000 {
                        return Err("Invalid REFERENCECONTROL_Reserved2");
                    }

                    // Check for optional name record
                    let check2 = read_u16(&dir_stream, &mut pos)?;
                    if check2 == 0x0016 {
                        let name_size = read_u32(&dir_stream, &mut pos)? as usize;
                        let _name = read_bytes(&dir_stream, &mut pos, name_size)?;
                        
                        let reserved = read_u16(&dir_stream, &mut pos)?;
                        if reserved != 0x003E {
                            return Err("Invalid REFERENCECONTROL_NameRecord_Reserved");
                        }
                        
                        let unicode_size = read_u32(&dir_stream, &mut pos)? as usize;
                        let _name_unicode = read_bytes(&dir_stream, &mut pos, unicode_size)?;
                    }

                    let reserved3 = if check2 == 0x0016 {
                        read_u16(&dir_stream, &mut pos)?
                    } else {
                        check2
                    };
                    if reserved3 != 0x0030 {
                        return Err("Invalid REFERENCECONTROL_Reserved3");
                    }

                    let _size_extended = read_u32(&dir_stream, &mut pos)?;
                    let size_libid = read_u32(&dir_stream, &mut pos)? as usize;
                    let _libid = read_bytes(&dir_stream, &mut pos, size_libid)?;
                    let _reserved4 = read_u32(&dir_stream, &mut pos)?;
                    let _reserved5 = read_u16(&dir_stream, &mut pos)?;
                    let _original_typelib = read_bytes(&dir_stream, &mut pos, 16)?;
                    let _cookie = read_u32(&dir_stream, &mut pos)?;
                },
                0x000D => {
                    // REFERENCEREGISTERED
                    let _size = read_u32(&dir_stream, &mut pos)?;
                    
                    let libid_size = read_u32(&dir_stream, &mut pos)? as usize;
                    let _libid = read_bytes(&dir_stream, &mut pos, libid_size)?;                    
                    let reserved1 = read_u32(&dir_stream, &mut pos)?;
                    if reserved1 != 0x0000 {
                        return Err("Invalid REFERENCEREGISTERED_Reserved1");
                    }
                    
                    let reserved2 = read_u16(&dir_stream, &mut pos)?;
                    if reserved2 != 0x0000 {
                        return Err("Invalid REFERENCEREGISTERED_Reserved2");
                    }
                },
                0x000E => {
                    // REFERENCEPROJECT
                    let _size = read_u32(&dir_stream, &mut pos)?;                    
                    let libid_abs_size = read_u32(&dir_stream, &mut pos)? as usize;
                    let _libid_abs = read_bytes(&dir_stream, &mut pos, libid_abs_size)?;
                    
                    let libid_rel_size = read_u32(&dir_stream, &mut pos)? as usize;
                    let _libid_rel = read_bytes(&dir_stream, &mut pos, libid_rel_size)?;
                    
                    let _major = read_u32(&dir_stream, &mut pos)?;
                    let _minor = read_u16(&dir_stream, &mut pos)?;
                },
                _ => return Err("Invalid reference type"),
            }
        }

        if last_check != 0x000F {
            return Err("Invalid PROJECTMODULES_Id");
        }
        
        let modules_size = read_u32(&dir_stream, &mut pos)?;
        if modules_size != 0x0002 {
            return Err("Invalid PROJECTMODULES_Size");
        }
        
        let modules_count = read_u16(&dir_stream, &mut pos)?;

        let cookie_id = read_u16(&dir_stream, &mut pos)?;
        if cookie_id != 0x0013 {
            return Err("Invalid ProjectCookie_Id");
        }
        
        let cookie_size = read_u32(&dir_stream, &mut pos)?;
        if cookie_size != 0x0002 {
            return Err("Invalid ProjectCookie_Size");
        }
        
        let _cookie = read_u16(&dir_stream, &mut pos)?;

        // Parse each module
        for _ in 0..modules_count {
            // Parse MODULENAME record
            let module_id = read_u16(&dir_stream, &mut pos)?;
            if module_id != 0x0019 {
                return Err("Invalid MODULENAME_Id");
            }
            
            let module_name_size = read_u32(&dir_stream, &mut pos)? as usize;
            let name_bytes = read_bytes(&dir_stream, &mut pos, module_name_size)?;
            let module_name = String::from_utf8_lossy(&name_bytes).to_string();

            let mut module_type = ModuleType::Unknown;
            let mut stream_name = String::new();
            let mut module_offset = 0u32;

            // Parse optional sections
            loop {
                let section_id = read_u16(&dir_stream, &mut pos)?;
                match section_id {
                    0x0047 => {
                        // MODULENAMEUNICODE
                        let unicode_size = read_u32(&dir_stream, &mut pos)? as usize;
                        let _unicode_name = read_bytes(&dir_stream, &mut pos, unicode_size)?;
                    },
                    0x001A => {
                        // MODULESTREAMNAME
                        let stream_size = read_u32(&dir_stream, &mut pos)? as usize;
                        let stream_bytes = read_bytes(&dir_stream, &mut pos, stream_size)?;
                        stream_name = String::from_utf8_lossy(&stream_bytes).to_string();
                        
                        let reserved = read_u16(&dir_stream, &mut pos)?;
                        if reserved != 0x0032 {
                            return Err("Invalid STREAMNAME_Reserved");
                        }
                        
                        let unicode_size = read_u32(&dir_stream, &mut pos)? as usize;
                        let _unicode_name = read_bytes(&dir_stream, &mut pos, unicode_size)?;
                    },
                    0x001C => {
                        // MODULEDOCSTRING
                        let doc_size = read_u32(&dir_stream, &mut pos)? as usize;
                        let _doc_string = read_bytes(&dir_stream, &mut pos, doc_size)?;
                        
                        let reserved = read_u16(&dir_stream, &mut pos)?;
                        if reserved != 0x0048 {
                            return Err("Invalid DOCSTRING_Reserved");
                        }
                        
                        let unicode_size = read_u32(&dir_stream, &mut pos)? as usize;
                        let _unicode_doc = read_bytes(&dir_stream, &mut pos, unicode_size)?;
                    },
                    0x0031 => {
                        // MODULEOFFSET
                        let offset_size = read_u32(&dir_stream, &mut pos)?;
                        if offset_size != 0x0004 {
                            return Err("Invalid OFFSET_Size");
                        }
                        module_offset = read_u32(&dir_stream, &mut pos)?;
                    },
                    0x001E => {
                        // MODULEHELPCONTEXT
                        let help_size = read_u32(&dir_stream, &mut pos)?;
                        if help_size != 0x0004 {
                            return Err("Invalid HELPCONTEXT_Size");
                        }
                        let _help_context = read_u32(&dir_stream, &mut pos)?;
                    },
                    0x002C => {
                        // MODULECOOKIE
                        let cookie_size = read_u32(&dir_stream, &mut pos)?;
                        if cookie_size != 0x0002 {
                            return Err("Invalid COOKIE_Size");
                        }
                        let _cookie = read_u16(&dir_stream, &mut pos)?;
                    },
                    0x0021 => {
                        module_type = ModuleType::Standard;
                        let _reserved = read_u32(&dir_stream, &mut pos)?;
                    },
                    0x0022 => {
                        module_type = ModuleType::Class;
                        let _reserved = read_u32(&dir_stream, &mut pos)?;
                    },
                    0x0025 => {
                        // MODULEREADONLY
                        let reserved = read_u32(&dir_stream, &mut pos)?;
                        if reserved != 0x0000 {
                            return Err("Invalid READONLY_Reserved");
                        }
                    },
                    0x0028 => {
                        // MODULEPRIVATE
                        let reserved = read_u32(&dir_stream, &mut pos)?;
                        if reserved != 0x0000 {
                            return Err("Invalid PRIVATE_Reserved");
                        }
                    },
                    0x002B => {
                        // TERMINATOR
                        let reserved = read_u32(&dir_stream, &mut pos)?;
                        if reserved != 0x0000 {
                            return Err("Invalid MODULE_Reserved");
                        }
                        break;
                    },
                    _ => return Err("Invalid module section ID"),
                }
            }

            // Get module code
            if let Some(module_data) = module_streams.get(&stream_name) {
                let code_data = if module_offset as usize >= module_data.len() {
                    return Err("Invalid module offset");
                } else {
                    &module_data[module_offset as usize..]
                };

                if !code_data.is_empty() {
                    let decompressed = Self::decompress_stream(code_data)?;
                    let code = String::from_utf8_lossy(&decompressed).to_string();
                    modules.insert(module_name.clone(), VbaModule {
                        name: module_name,
                        code,
                        module_type,
                    });
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

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, &'static str> {
    if *pos + 2 > data.len() {
        return Err("Not enough bytes to read u16");
    }
    let value = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, &'static str> {
    if *pos + 4 > data.len() {
        return Err("Not enough bytes to read u32");
    }
    let value = u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(value)
}

fn read_bytes(data: &[u8], pos: &mut usize, len: usize) -> Result<Vec<u8>, &'static str> {
    if *pos + len > data.len() {
        return Err("Not enough bytes to read");
    }
    let bytes = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(bytes)
}
