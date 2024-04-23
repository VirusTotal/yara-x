---
title: "hash"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "hash-module"
weight: 325
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `hash` module allows you to calculate hashes (MD5, SHA1, SHA256) and
checksums from portions of your file and create signatures based on those
hashes.

## Functions

{{< callout context="caution" title="Important">}}

Hashes returned by the functions below are always in lowercase.

{{< /callout >}}

### md5(offset, size)

Returns the MD5 hash for size bytes starting at offset. When scanning a running
process the offset argument should be a virtual address within the process
address space. The returned string is always in lowercase.

Example: `hash.md5(0, filesize) == "feba6c919e3797e7778e8f2e85fa033d"`

### md5(string)

Returns the MD5 hash for the given string.

Example: `hash.md5("dummy") == "275876e34cf609db118f3d84b799a790"`

### sha1(offset, size)

Returns the SHA1 hash for the size bytes starting at offset. When scanning a
running process the offset argument should be a virtual address within the
process address space. The returned string is always in lowercase.

### sha1(string)

Returns the SHA1 hash for the given string.

### sha256(offset, size)

Returns the SHA256 hash for the size bytes starting at offset. When scanning a
running process the offset argument should be a virtual address within the
process address space. The returned string is always in lowercase.

### sha256(string)

Returns the SHA256 hash for the given string.

### checksum32(offset, size)

Returns a 32-bit checksum for the size bytes starting at offset. The checksum is
just the sum of all the bytes (unsigned).

### checksum32(string)

Returns a 32-bit checksum for the given string. The checksum is just the sum of
all the bytes in the string (unsigned).

### crc32(offset, size)

Returns a crc32 checksum for the size bytes starting at offset.

### crc32(string)

Returns a crc32 checksum for the given string.