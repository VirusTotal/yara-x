---
title: "ooxml"
description: ""
summary: ""
date: 2026-10-08T00:00:00+01:00
lastmod: 2026-10-08T00:00:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "ooxml-module"
weight: 750
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `ooxml` module parses Office Open XML (OOXML) documents, the format of
modern Microsoft Office files such as DOCX, XLSX and PPTX. OOXML documents are
ZIP archives that follow the Open Packaging Conventions; the module reads the
ZIP end of central directory record and the central directory file headers,
and exposes the metadata of every entry. Entries are not decompressed.

A file is recognized as an OOXML document when one of its entries is named
`[Content_Types].xml`. Other ZIP archives are parsed too, with `is_ooxml` set
to false, so the module can also be used to inspect ZIP archives in general.
Only files that start with a ZIP local file header (`PK\x03\x04`) are parsed.

The per-entry metadata (timestamps, host operating system, ZIP version and
flags) reflects the tool that created the document, which makes it useful for
clustering documents produced by the same builder.

This module is still experimental and is not built by default. Enable it with
the `ooxml-module` feature.

-------

## Module structure

| Field                     | Type                  | Description                                                                                                                  |
|---------------------------|-----------------------|------------------------------------------------------------------------------------------------------------------------------|
| is_ooxml                  | bool                  | True if the file is an OOXML document, false for other ZIP archives. Undefined if the file is not a ZIP archive.             |
| number_of_on_disk_entries | integer               | Number of central directory entries on this disk.                                                                            |
| number_of_total_entries   | integer               | Total number of central directory entries. Normally equal to `number_of_on_disk_entries`.                                    |
| central_dir_size          | integer               | Size of the central directory in bytes.                                                                                      |
| central_dir_offset        | integer               | Offset of the central directory within the file.                                                                             |
| zip_comment_len           | integer               | Length of the ZIP file comment in bytes.                                                                                     |
| zip_comment_str           | string                | ZIP file comment. Undefined if the archive has no comment.                                                                   |
| entries                   | [Entry](#entry) array | Entries in the central directory.                                                                                            |

### Entry

| Field                    | Type    | Description                                                                                                                         |
|--------------------------|---------|-------------------------------------------------------------------------------------------------------------------------------------|
| name_string              | string  | Name of the entry (e.g. `word/document.xml`), as stored in the archive. Undefined if the entry has an empty name.                     |
| name_length              | integer | Length of the entry's name in bytes. Undefined if the name is empty.                                                                |
| compressed_size          | integer | Compressed size of the entry in bytes.                                                                                              |
| uncompressed_size        | integer | Uncompressed size of the entry in bytes.                                                                                            |
| crc32_checksum           | integer | CRC-32 checksum of the entry's uncompressed data.                                                                                   |
| compression_method_value | integer | Raw value of the compression method (e.g. 8 for Deflate).                                                                           |
| compression_method_name  | string  | Name of the compression method: `Store`, `Shrink`, `Reduce1`-`Reduce4`, `Implode`, `Deflate`, `Deflate64`, `BZIP2`, `LZMA`, `LZ77`, `PPMd`, or `Unknown`. |
| mod_time_raw             | integer | Last modification time in MS-DOS format, as stored in the archive.                                                                  |
| mod_date_raw             | integer | Last modification date in MS-DOS format, as stored in the archive.                                                                  |
| flags                    | integer | General purpose bit flags.                                                                                                          |
| version_needed           | integer | Minimum ZIP specification version needed to extract the entry.                                                                      |
| version_made_by          | integer | Raw "version made by" value. The upper byte identifies the host operating system and the lower byte the ZIP specification version. |
| os_name                  | string  | Host operating system that created the entry (e.g. `Unix`, `NTFS`, `FAT`), derived from `version_made_by`, or `Unknown`.            |
| spec_version             | integer | ZIP specification version used to create the entry (e.g. 20 for version 2.0), derived from `version_made_by`.                       |

#### Examples

```
import "ooxml"

rule ooxml_with_media {
  condition:
    ooxml.is_ooxml and
    for any e in ooxml.entries : (
      e.name_string startswith "word/media/"
    )
}
```

```
import "ooxml"

rule ooxml_created_on_unix {
  condition:
    ooxml.is_ooxml and
    for all e in ooxml.entries : (e.os_name == "Unix")
}
```

```
import "ooxml"

rule zip_with_inconsistent_entry_counts {
  condition:
    ooxml.number_of_on_disk_entries != ooxml.number_of_total_entries
}
```
