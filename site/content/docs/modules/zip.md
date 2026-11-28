---
title: "zip"
description: ""
summary: ""
date: 2026-11-28T10:00:00:00+00:00
lastmod: 2026-11-28T10:00:00:00+00:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "zip-module"
weight: 1100
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `zip` module parses ZIP archives and exposes the list of entries they
contain, together with the compression method and the size of each one. It
reads the archive's metadata only, so a rule can reason about what an archive
holds without the contents being decompressed.

This also covers the many formats that are ZIP archives with another extension,
such as JAR, APK, DOCX, XLSX, ODT and EPUB.

-------

## Module structure

| Field   | Type                  | Description                            |
|---------|-----------------------|----------------------------------------|
| is_zip  | bool                  | True if the data is a ZIP archive.     |
| entries | [Entry](#entry) array | One entry per file or directory found. |

### Entry

These are the fields in each entry of the `entries` array.

| Field             | Type                          | Description                                                 |
|-------------------|-------------------------------|-------------------------------------------------------------|
| file_path         | string                        | Path of the entry as stored in the archive.                 |
| compression       | [Compression](#compression)   | Compression method used for the entry.                      |
| uncompressed_size | integer                       | Size of the entry once decompressed, in bytes.              |
| compressed_size   | integer                       | Size of the entry as stored in the archive, in bytes.       |

`file_path` is the path exactly as the archive stores it, which means it can
contain directory separators, and it is decoded as UTF-8 replacing any invalid
sequence, so it is not guaranteed to round-trip to the original bytes.

Both sizes come from the entry's own header and are not verified against the
data, so an archive can claim whatever it likes. Comparing the two is a cheap
way to spot an entry whose declared ratio is implausible.

Entries that cannot be parsed are skipped, and no more than 100000 entries are
reported for a single archive.

#### Example

```
import "zip"

rule apk_with_dex_at_the_root {
    condition:
        zip.is_zip and
        for any entry in zip.entries : (
            entry.file_path == "classes.dex"
        )
}
```

### Compression

These are the possible values of the `compression` field. The names come from
the compression method numbers defined by the ZIP specification, and an entry
using a method that is not in this list is reported as `UNKNOWN`.

| Name              | Value |
|-------------------|------:|
| STORED            |     0 |
| SHRUNK            |     1 |
| REDUCED_1         |     2 |
| REDUCED_2         |     3 |
| REDUCED_3         |     4 |
| REDUCED_4         |     5 |
| IMPLODED          |     6 |
| DEFLATED          |     8 |
| DEFLATE64         |     9 |
| PKWARE_IMPLODING  |    10 |
| BZIP2             |    12 |
| LZMA              |    14 |
| ZSTD              |    93 |
| XZ                |    95 |
| UNKNOWN           |   255 |

#### Example

```
import "zip"

rule stored_entry_larger_than_1mb {
    condition:
        for any entry in zip.entries : (
            entry.compression == zip.STORED and
            entry.uncompressed_size > 1048576
        )
}
```
