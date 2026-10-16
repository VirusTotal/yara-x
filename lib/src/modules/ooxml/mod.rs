/*! YARA module that parses Office Open XML (OOXML) documents.

OOXML (ISO/IEC 29500) is the format of modern Microsoft Office documents such
as DOCX, XLSX and PPTX. These files are ZIP archives that follow the Open
Packaging Conventions. This module parses the ZIP end of central directory
record and the central directory file headers, and exposes the metadata of
every entry (name, sizes, CRC-32, compression method, timestamps, flags, and
the host operating system and ZIP version that created it). Entries are not
decompressed.

A file is considered an OOXML document when one of its entries is named
`[Content_Types].xml`. Other ZIP archives are also parsed, with `is_ooxml`
set to false.

Read more about the ZIP format here:
<https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT>
*/

use crate::errors::ModuleError;
use crate::mods::prelude::*;
use crate::modules::protos::ooxml::*;

#[cfg(test)]
mod tests;

const SIG_LOCAL_FILE_HEADER: u32 = 0x04034b50;
const SIG_CENTRAL_DIR: u32 = 0x02014b50;
const SIG_END_OF_CENTRAL_DIR: u32 = 0x06054b50;

/// Size of the end of central directory record, without the comment.
const EOCD_SIZE: usize = 22;
/// Size of a central directory file header, without the variable fields.
const CD_HEADER_SIZE: usize = 46;
/// Maximum length of the ZIP file comment.
const MAX_COMMENT_SIZE: usize = 0xFFFF;

const CONTENT_TYPES: &[u8] = b"[Content_Types].xml";

fn main(_ctx: &mut ModuleContext, data: &[u8]) -> Result<Ooxml, ModuleError> {
    Ok(parse(data))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Returns the offset of the end of central directory record.
///
/// The record is searched backwards from the end of the file, and it is
/// accepted only if its comment ends exactly at the end of the file.
fn find_eocd(data: &[u8]) -> Option<usize> {
    let last = data.len().checked_sub(EOCD_SIZE)?;
    let first = last.saturating_sub(MAX_COMMENT_SIZE);
    (first..=last).rev().find(|&offset| {
        read_u32(data, offset) == Some(SIG_END_OF_CENTRAL_DIR)
            && read_u16(data, offset + 20).is_some_and(|comment_len| {
                offset + EOCD_SIZE + comment_len as usize == data.len()
            })
    })
}

fn compression_method_name(method: u16) -> &'static str {
    match method {
        0 => "Store",
        1 => "Shrink",
        2 => "Reduce1",
        3 => "Reduce2",
        4 => "Reduce3",
        5 => "Reduce4",
        6 => "Implode",
        8 => "Deflate",
        9 => "Deflate64",
        12 => "BZIP2",
        14 => "LZMA",
        19 => "LZ77",
        98 => "PPMd",
        _ => "Unknown",
    }
}

fn os_name(host: u8) -> &'static str {
    match host {
        0 => "FAT",
        1 => "Amiga",
        2 => "VMS",
        3 => "Unix",
        4 => "VM/CMS",
        5 => "Atari ST",
        6 => "HPFS",
        7 => "Macintosh",
        10 => "NTFS",
        11 => "MVS",
        14 => "VFAT",
        18 => "IBM OS/2",
        19 => "Macintosh OSX",
        _ => "Unknown",
    }
}

/// Parses `data` and returns the module's output.
///
/// Files that don't start with a local file header, or don't have a valid
/// end of central directory record, produce an empty output.
fn parse(data: &[u8]) -> Ooxml {
    let mut ooxml = Ooxml::new();

    if read_u32(data, 0) != Some(SIG_LOCAL_FILE_HEADER) {
        return ooxml;
    }

    let Some(eocd) = find_eocd(data) else {
        return ooxml;
    };

    // All these reads are within bounds, as `find_eocd` guarantees that
    // there are at least EOCD_SIZE bytes after `eocd`.
    let on_disk_entries = read_u16(data, eocd + 8).unwrap();
    let total_entries = read_u16(data, eocd + 10).unwrap();
    let cd_size = read_u32(data, eocd + 12).unwrap();
    let cd_offset = read_u32(data, eocd + 16).unwrap();
    let comment_len = read_u16(data, eocd + 20).unwrap() as usize;

    ooxml.set_is_ooxml(false);
    ooxml.set_number_of_on_disk_entries(on_disk_entries.into());
    ooxml.set_number_of_total_entries(total_entries.into());
    ooxml.set_central_dir_size(cd_size);
    ooxml.set_central_dir_offset(cd_offset);
    ooxml.set_zip_comment_len(comment_len as u32);

    if comment_len > 0 {
        let start = eocd + EOCD_SIZE;
        ooxml.set_zip_comment_str(data[start..start + comment_len].to_vec());
    }

    if cd_offset as usize + cd_size as usize > data.len() {
        return ooxml;
    }

    let mut offset = cd_offset as usize;

    for _ in 0..total_entries {
        if read_u32(data, offset) != Some(SIG_CENTRAL_DIR) {
            break;
        }

        let Some(header) = data.get(offset..offset + CD_HEADER_SIZE) else {
            break;
        };

        let u16_at = |pos: usize| read_u16(header, pos).unwrap();
        let u32_at = |pos: usize| read_u32(header, pos).unwrap();

        let version_made_by = u16_at(4);
        let method = u16_at(10);
        let name_len = u16_at(28) as usize;
        let extra_len = u16_at(30) as usize;
        let file_comment_len = u16_at(32) as usize;

        let name_start = offset + CD_HEADER_SIZE;
        let Some(name) = data.get(name_start..name_start + name_len) else {
            break;
        };

        if name == CONTENT_TYPES {
            ooxml.set_is_ooxml(true);
        }

        let mut entry = Entry::new();

        entry.set_version_made_by(version_made_by.into());
        entry.set_version_needed(u16_at(6).into());
        entry.set_flags(u16_at(8).into());
        entry.set_compression_method_value(method.into());
        entry.set_compression_method_name(
            compression_method_name(method).to_string(),
        );
        entry.set_mod_time_raw(u16_at(12).into());
        entry.set_mod_date_raw(u16_at(14).into());
        entry.set_crc32_checksum(u32_at(16));
        entry.set_compressed_size(u32_at(20));
        entry.set_uncompressed_size(u32_at(24));
        entry.set_os_name(os_name((version_made_by >> 8) as u8).to_string());
        entry.set_spec_version((version_made_by & 0xff).into());

        if !name.is_empty() {
            entry.set_name_string(name.to_vec());
            entry.set_name_length(name_len as u32);
        }

        ooxml.entries.push(entry);

        offset = name_start + name_len + extra_len + file_comment_len;
    }

    ooxml
}

register_module!("ooxml", Ooxml, main);
