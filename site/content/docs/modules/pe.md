---
title: "pe"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "pe-module"
weight: 800
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `pe` module allows you to create more fine-grained rules for [Portable
Executable (PE)](https://en.wikipedia.org/wiki/Portable_Executable) files by
using attributes and features of the PE file format. This module exposes most of
the fields present in a PE header and provides functions which can be used to
write more expressive and targeted rules. Let's see some examples:

```yara
import "pe"

rule single_section {
    condition:
        pe.number_of_sections == 1
}

rule control_panel_applet {
    condition:
        pe.exports("CPlApplet")
}

rule is_dll {
    condition:
        pe.characteristics & pe.DLL != 0
}

rule is_pe {
    condition:
        pe.is_pe
}
```

-------

## Functions

### exports(fn_name)

Returns true if the PE exports a function with the given name, or false
otherwise.

### exports(fn_regex)

Returns true if the PE exports a function whose name matches the given regular
expression, or false otherwise.

### exports(ordinal)

Returns true if the PE exports a function with the given ordinal, or false if
otherwise.

### exports_index(fn_name)

Returns the index into the `export_details` array for the first exported
function that matches the given name. The result is `undefined` if no
function with such a name exists.

### exports_index(fn_regex)

Returns the index into the `export_details` array for the first exported
function that matches the given regular expression. The result is `undefined` if
none of the functions matches.

### exports_index(ordinal)

Returns the index into the `export_details` array for the first exported
function that has the given ordinal number. The result is `undefined` if no
function exists with such an ordinal exists.

### imports(dll_name)

Returns the number of functions that the PE imports from the given DLL. The
DLL name is case-insensitive.

### imports(dll_name, fn_name)

Returns true if the PE imports the given function from the given DLL. The DLL
name is case-insensitive, but the function name is case-sensitive.

### imports(dll_name, ordinal)

Returns true if the PE imports the given function by ordinal from the given DLL.
The DLL name is case-insensitive.

### imports(dll_regex, fn_regex)

Returns the number of functions imported by the PE where the DLL name matches
`dll_regexp` and the function name matches `fn_regexp`. Both arguments are
case-sensitive, unless you use the `/i` modifier in the regexp.

#### Example

```
import "pe"

rule ProcessMemory {
    condition:
        pe.imports(/kernel32.dll/i, /(Read|Write)ProcessMemory/) > 0
}
```

### imports(type, dll_name, fn_name)

Returns true if the PE imports `fn_name` from `dll_name`. The DLL
name is case-insensitive. `type` allows to specify the kind of imports should be
taken into account, the allowed values are:

|                      |                                   |
|----------------------|-----------------------------------|
| `pe.IMPORT_STANDARD` | Standard imports only             |
| `pe.IMPORT_DELAYED`  | Delayed imports only              |
| `pe.IMPORT_ANY`      | Both standard and delayed imports |

#### Example

```
import "pe"

rule ProcessMemory {
    condition:
        pe.imports(pe.IMPORT_DELAYED, "kernel32.dll", "WriteProcessMemory")
}
```

### is_32bit()

Returns true if the file is a 32-bit PE.

### is_64bit()

Returns true if the file is a 64-bit PE.

### is_dll()

Returns true if the file is Dynamic Link Library (DLL).

### rva_to_offset(rva)

Given a relative virtual address (RVA) returns the corresponding file offset.

### calculate_checksum()

Calculate the PE checksum. Useful for checking if the checksum in the header is
correct.

#### Example

```
import "pe"

rule WrongChecksum {
    condition:
        pe.calculate_checksum() != pe.checksum
}
```

### section_index(name)

Returns the index into the `sections` array for the section that has the given
name. The `name` argument is case-sensitive.

### section_index(offset)

Returns the index into the `sections` array for the section that contains
the given file offset.

### imphash()

Returns the import hash (or imphash) for the PE. The imphash is an MD5 hash of
the PE's import table after some normalization. The imphash for a PE can be also
computed with [pefile](https://github.com/erocarrera/pefile) and you can find
more information
in [Mandiant's blog](https://www.mandiant.com/resources/blog/tracking-malware-import-hashing).

{{< callout title="Notice">}}

The returned hash string is always in lowercase.

{{< /callout >}}

### rich_signature.version(version, [toolid])

The PE rich signature contains information about the tools involved in the
creation of the PE file. This function returns the number of tools that
matches the given version and toolid, where toolid is optional.

#### Example

```
import "pe"

rule WrongChecksum {
    condition:
        pe.rich_signature.version(24215, 261) == 61
}
```

### rich_signature.toolid(toolid, [version])

This function is similar to `rich_signature.version`, but the toolid argument
is required while version is optional.

------

## Module structure

| Field                                | Type                            | Description                                      |
|--------------------------------------|---------------------------------|--------------------------------------------------|
| is_pe                                | bool                            | True if the file is PE                           |
| is_signed                            | bool                            | True if the Authenticode signature is correct    |
| machine                              | [Machine](#machine)             | Machine type                                     |
| subsystem                            | [Subsystem](#subsystem)         | Subsystem type                                   |
| os_version                           | [Version](#version)             | OS version                                       |
| subsystem_version                    | [Version](#version)             | Subsystem version                                |
| image_version                        | [Version](#version)             | Image version                                    |
| linker_version                       | [Version](#version)             | Linker version                                   |
| opthdr_magic                         | [OptionalMagic](#optionalmagic) | Magic in optional headers                        |
| characteristics                      | integer                         | [Characteristics](#characteristics) flags        |
| dll_characteristics                  | integer                         | [DllCharacteristics](#dllcharacteristics) flags  |
| timestamp                            | integer                         | PE timestamp (as Unix timestamp)                 |
| image_base                           | integer                         | Image base                                       |
| checksum                             | integer                         | PE checksum                                      |
| base_of_code                         | integer                         | Base of code                                     |
| base_of_data                         | integer                         | Base of data                                     |
| entry_point                          | integer                         | Entry point as a file offset                     |
| entry_point_raw                      | integer                         | Entry point as it appears in the PE header (RVA) |
| dll_name                             | string                          | DLL name                                         |
| export_timestamp                     | integer                         | Exports timestamp (as Unix timestamp)            |
| section_alignment                    | integer                         | Section alignment                                |
| file_alignment                       | integer                         | File alignment                                   |
| loader_flags                         | integer                         | Loader flags                                     |
| size_of_optional_header              | integer                         | Size of optional header                          |
| size_of_code                         | integer                         | Size of code                                     |
| size_of_initialized_data             | integer                         | Size of initialized data                         |
| size_of_uninitialized_data           | integer                         | Size of uninitialized data                       |
| size_of_image                        | integer                         | Size of image                                    |
| size_of_headers                      | integer                         | Size of headers                                  |
| size_of_stack_reserve                | integer                         | Size of stack reserve                            |
| size_of_stack_commit                 | integer                         | Size of stack commit                             |
| size_of_heap_reserve                 | integer                         | Size of heap reserve                             |
| size_of_heap_commit                  | integer                         | Size of heap commit                              |
| pointer_to_symbol_table              | integer                         | File offset of symbol table                      |
| win32_version_value                  | integer                         | Win32 version                                    |
| number_of_symbols                    | integer                         | Number of symbols                                |
| number_of_rva_and_sizes              | integer                         | Number of                                        |
| number_of_sections                   | integer                         | Length of `sections`                             |
| number_of_imported_functions         | integer                         | Total number of imported functions               |
| number_of_delayed_imported_functions | integer                         | Total number of delayed imported functions       |
| number_of_resources                  | integer                         | Length of `resources`                            |
| number_of_version_infos              | integer                         | Length of `version_info_list`                    |
| number_of_imports                    | integer                         | Length of `import_details`                       |
| number_of_delayed_imports            | integer                         | Length of `delayed_import_details`               |
| number_of_exports                    | integer                         | Length of `export_details`                       |
| number_of_signatures                 | integer                         | Length of `signatures`                           |
| version_info                         | dictionary                      | Dictionary with PE version information           |
| version_info_list                    | [KeyValue](#keyvalue) array     | Like `version_info` but as array                 |
| rich_signature                       | [RichSignature](#richSignature) | Rich signature information                       |
| pdb_path                             | string                          | PDB path                                         |
| sections                             | [Section](#section) array       | Sections                                         |
| data_directories                     | [DirEntry](#dirEntry) array     | Data directory entries                           |
| resource_timestamp                   | integer                         | Resource timestamp (as Unix timestamp)           |
| resource_version                     | [Version](#version)             | Resource version                                 |
| resources                            | [Resource](#resource) array     | Resources                                        |
| import_details                       | [Import](#import) array         | Imports information                              |
| delayed_import_details               | [Import](#import) array         | Delayed imports information                      |
| export_details                       | [Export](#export) array         | Exports information                              |
| signatures                           | [Signature](#signature) array   | Signatures information                           |
| overlay                              | [Overlay](#overlay)             | PE overlay details                               |

### Certificate

This is the structure of each item in the `certificates` array.

| Field         | Type    |
|---------------|---------|
| issuer        | string  |
| subject       | string  |
| thumbprint    | string  |
| version       | integer |
| algorithm     | string  |
| algorithm_oid | string  |
| serial        | string  |
| not_before    | integer |
| not_after     | integer |

### CounterSignature

| Field      | Type                              |
|------------|-----------------------------------|
| verified   | bool                              |
| sign_time  | integer                           |
| digest     | string                            |
| digest_alg | string                            |
| chain      | [Certificate](#certificate) array |

### DirEntry

| Field           | Type    |
|-----------------|---------|
| virtual_address | integer |
| size            | integer |

### Export

| Field        | Type    |
|--------------|---------|
| name         | string  |
| ordinal      | integer |
| rva          | integer |
| offset       | integer |
| forward_name | string  |

### Function

| Field   | Type    |
|---------|---------|
| name    | string  |
| ordinal | integer |
| rva     | integer |

### Import

| Field               | Type                        |
|---------------------|-----------------------------|
| library_name        | string                      |
| number_of_functions | integer                     |
| functions           | [Function](#function) array |

### KeyValue

| Field | Type   |
|-------|--------|
| key   | string |
| value | string |

### Overlay

| Field  | Type    |
|--------|---------|
| offset | integer |
| size   | integer |

### VersionInfoEntry

| Field | Type   |
|-------|--------|
| key   | string |
| value | string |

### Resource

| Field           | Type                          |
|-----------------|-------------------------------|
| length          | integer                       |
| rva             | integer                       |
| offset          | integer                       |
| type            | [ResourceType](#resourcetype) |
| id              | integer                       |
| language        | integer                       |
| type_string     | string                        |
| name_string     | string                        |
| language_string | string                        |

### RichSignature

| Field      | Type                        |
|------------|-----------------------------|
| offset     | integer                     |
| length     | integer                     |
| key        | integer                     |
| raw_data   | string                      |
| clear_data | string                      |
| tools      | [RichTool](#richtool) array |

### RichTool

| Field   | Type    |
|---------|---------|
| toolid  | integer |
| version | integer |
| times   | integer |

### Section

| Field                   | Type    |
|-------------------------|---------|
| name                    | string  |
| full_name               | string  |
| characteristics         | integer |
| raw_data_size           | integer |
| raw_data_offset         | integer |
| virtual_address         | integer |
| virtual_size            | integer |
| pointer_to_relocations  | integer |
| pointer_to_line_numbers | integer |
| number_of_relocations   | integer |
| number_of_line_numbers  | integer |

### Signature

Structure of each of the items in the `signatures` array.

| Field                       | Type                                        |
|-----------------------------|---------------------------------------------|
| subject                     | string                                      |
| issuer                      | string                                      |
| thumbprint                  | string                                      |
| version                     | integer                                     |
| algorithm                   | string                                      |
| algorithm_oid               | string                                      |
| serial                      | string                                      |
| not_before                  | integer                                     |
| not_after                   | integer                                     |
| verified                    | bool                                        |
| digest_alg                  | string                                      |
| digest                      | string                                      |
| file_digest                 | string                                      |
| number_of_certificates      | integer                                     |
| number_of_countersignatures | integer                                     |
| signer_info                 | [SignerInfo](#signerinfo)                   |
| certificates                | [Certificate](#certificate) array           | 
| countersignatures           | [CounterSignature](#countersignature) array | 

#### Example

```
import "pe"

rule NotVerified {
    condition:
        for any sig in pe.signatures : (
            sig.subject contains "Microsoft" and
            not sig.verified
        )
}
```

### SignerInfo

| Field        | Type                              |
|--------------|-----------------------------------|
| program_name | string                            |
| digest       | string                            |
| digest_alg   | string                            |
| chain        | [Certificate](#certificate) array |

### Version

The structures of fields
like `os_version`, `subsystem_version`, `image_version`,
`linker_version` and `resource_version`.

| Field | Type    |
|-------|---------|
| major | integer |
| minor | integer |

#### Example

```
import "pe"

rule Windows_5_2 {
    condition:
        pe.os_version.major == 5 and 
        pe.os_version.minor == 2
}
```

### Characteristics

Possible flags found in the `characteristics` field.

| Name                    | Number | Description                                                      |
|-------------------------|--------|------------------------------------------------------------------|
| RELOCS_STRIPPED         | 0x0001 | Relocation info stripped from file.                              |
| EXECUTABLE_IMAGE        | 0x0002 | File is executable (i.e. no unresolved external references).     |
| LINE_NUMS_STRIPPED      | 0x0004 | Line numbers stripped from file.                                 |
| LOCAL_SYMS_STRIPPED     | 0x0008 | Local symbols stripped from file.                                |
| AGGRESIVE_WS_TRIM       | 0x0010 | Aggressively trim working set                                    |
| LARGE_ADDRESS_AWARE     | 0x0020 | App can handle &gt;2gb addresses                                 |
| BYTES_REVERSED_LO       | 0x0080 | Bytes of machine word are reversed.                              |
| MACHINE_32BIT           | 0x0100 | 32 bit word machine.                                             |
| DEBUG_STRIPPED          | 0x0200 | Debugging info stripped from file in .DBG file                   |
| REMOVABLE_RUN_FROM_SWAP | 0x0400 | If Image is on removable media, copy and run from the swap file. |
| NET_RUN_FROM_SWAP       | 0x0800 | If Image is on Net, copy and run from the swap file.             |
| SYSTEM                  | 0x1000 | System File.                                                     |
| DLL                     | 0x2000 | File is a DLL.s                                                  |
| UP_SYSTEM_ONLY          | 0x4000 | File should only be run on a UP machine                          |
| BYTES_REVERSED_HI       | 0x8000 | Bytes of machine word are reversed.                              |

#### Example

```
import "pe"

rule IsDLL {
    condition:
        pe.characteristics & pe.DLL != 0
}
```

### DllCharacteristics

Possible flags found in the `dll_characteristics` field.

| Name                  | Number |
|-----------------------|--------|
| HIGH_ENTROPY_VA       | 0x0020 |
| DYNAMIC_BASE          | 0x0040 |
| FORCE_INTEGRITY       | 0x0080 |
| NX_COMPAT             | 0x0100 |
| NO_ISOLATION          | 0x0200 |
| NO_SEH                | 0x0400 |
| NO_BIND               | 0x0800 |
| APPCONTAINER          | 0x1000 |
| WDM_DRIVER            | 0x2000 |
| GUARD_CF              | 0x4000 |
| TERMINAL_SERVER_AWARE | 0x8000 |

#### Example

```
import "pe"

rule WdmDriver {
    condition:
        pe.dll_characteristics & pe.WDM_DRIVER != 0
}
```

### DirectoryEntry

| Name                                 | Number |
|--------------------------------------|--------|
| IMAGE_DIRECTORY_ENTRY_EXPORT         | 0      |
| IMAGE_DIRECTORY_ENTRY_IMPORT         | 1      |
| IMAGE_DIRECTORY_ENTRY_RESOURCE       | 2      |
| IMAGE_DIRECTORY_ENTRY_EXCEPTION      | 3      |
| IMAGE_DIRECTORY_ENTRY_SECURITY       | 4      |
| IMAGE_DIRECTORY_ENTRY_BASERELOC      | 5      |
| IMAGE_DIRECTORY_ENTRY_DEBUG          | 6      |
| IMAGE_DIRECTORY_ENTRY_COPYRIGHT      | 7      |
| IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   | 8      |
| IMAGE_DIRECTORY_ENTRY_GLOBALPTR      | 9      |
| IMAGE_DIRECTORY_ENTRY_TLS            | 10     |
| IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    | 11     |
| IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   | 12     |
| IMAGE_DIRECTORY_ENTRY_IAT            | 13     |
| IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   | 14     |
| IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR | 15     |

### ImportFlags

| Name            | Number |
|-----------------|--------|
| IMPORT_STANDARD | 1      |
| IMPORT_DELAYED  | 2      |
| IMPORT_ANY      | 3      |

### Machine

Each of the possible values in the `machine` field.

| Name              | Number |
|-------------------|--------|
| MACHINE_UNKNOWN   | 0      |
| MACHINE_AM33      | 467    |
| MACHINE_AMD64     | 34404  |
| MACHINE_ARM       | 448    |
| MACHINE_ARMNT     | 452    |
| MACHINE_ARM64     | 43620  |
| MACHINE_EBC       | 3772   |
| MACHINE_I386      | 332    |
| MACHINE_IA64      | 512    |
| MACHINE_M32R      | 36929  |
| MACHINE_MIPS16    | 614    |
| MACHINE_MIPSFPU   | 870    |
| MACHINE_MIPSFPU16 | 1126   |
| MACHINE_POWERPC   | 496    |
| MACHINE_POWERPCFP | 497    |
| MACHINE_R4000     | 358    |
| MACHINE_SH3       | 418    |
| MACHINE_SH3DSP    | 419    |
| MACHINE_SH4       | 422    |
| MACHINE_SH5       | 424    |
| MACHINE_THUMB     | 450    |
| MACHINE_WCEMIPSV2 | 361    |

#### Example

```
import "pe"

rule ARM {
    condition:
        pe.machine == pe.MACHINE_ARM
}
```

### OptionalMagic

| Name                          | Number |
|-------------------------------|--------|
| IMAGE_NT_OPTIONAL_HDR32_MAGIC | 267    |
| IMAGE_NT_OPTIONAL_HDR64_MAGIC | 523    |
| IMAGE_ROM_OPTIONAL_HDR_MAGIC  | 263    |

### ResourceType

https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types?redirectedfrom=MSDN

| Name                       | Number |
|----------------------------|--------|
| RESOURCE_TYPE_CURSOR       | 1      |
| RESOURCE_TYPE_BITMAP       | 2      |
| RESOURCE_TYPE_ICON         | 3      |
| RESOURCE_TYPE_MENU         | 4      |
| RESOURCE_TYPE_DIALOG       | 5      |
| RESOURCE_TYPE_STRING       | 6      |
| RESOURCE_TYPE_FONTDIR      | 7      |
| RESOURCE_TYPE_FONT         | 8      |
| RESOURCE_TYPE_ACCELERATOR  | 9      |
| RESOURCE_TYPE_RCDATA       | 10     |
| RESOURCE_TYPE_MESSAGETABLE | 11     |
| RESOURCE_TYPE_GROUP_CURSOR | 12     |
| RESOURCE_TYPE_GROUP_ICON   | 14     |
| RESOURCE_TYPE_VERSION      | 16     |
| RESOURCE_TYPE_DLGINCLUDE   | 17     |
| RESOURCE_TYPE_PLUGPLAY     | 19     |
| RESOURCE_TYPE_VXD          | 20     |
| RESOURCE_TYPE_ANICURSOR    | 21     |
| RESOURCE_TYPE_ANIICON      | 22     |
| RESOURCE_TYPE_HTML         | 23     |
| RESOURCE_TYPE_MANIFEST     | 24     |

### SectionCharacteristics

| Name                           | Number |
|--------------------------------|--------|
| SECTION_NO_PAD                 | 1      |
| SECTION_CNT_CODE               | 2      |
| SECTION_CNT_INITIALIZED_DATA   | 3      |
| SECTION_CNT_UNINITIALIZED_DATA | 4      |
| SECTION_LNK_OTHER              | 5      |
| SECTION_LNK_INFO               | 6      |
| SECTION_LNK_REMOVE             | 7      |
| SECTION_LNK_COMDAT             | 8      |
| SECTION_NO_DEFER_SPEC_EXC      | 9      |
| SECTION_GPREL                  | 10     |
| SECTION_ALIGN_1BYTES           | 11     |
| SECTION_ALIGN_2BYTES           | 12     |
| SECTION_ALIGN_4BYTES           | 13     |
| SECTION_ALIGN_8BYTES           | 14     |
| SECTION_ALIGN_16BYTES          | 15     |
| SECTION_ALIGN_32BYTES          | 16     |
| SECTION_ALIGN_64BYTES          | 17     |
| SECTION_ALIGN_128BYTES         | 18     |
| SECTION_ALIGN_256BYTES         | 19     |
| SECTION_ALIGN_512BYTES         | 20     |
| SECTION_ALIGN_1024BYTES        | 21     |
| SECTION_ALIGN_2048BYTES        | 22     |
| SECTION_ALIGN_4096BYTES        | 23     |
| SECTION_ALIGN_8192BYTES        | 24     |
| SECTION_ALIGN_MASK             | 25     |
| SECTION_LNK_NRELOC_OVFL        | 26     |
| SECTION_MEM_DISCARDABLE        | 27     |
| SECTION_MEM_NOT_CACHED         | 28     |
| SECTION_MEM_NOT_PAGED          | 29     |
| SECTION_MEM_SHARED             | 30     |
| SECTION_MEM_EXECUTE            | 31     |
| SECTION_MEM_READ               | 32     |
| SECTION_MEM_WRITE              | 33     |
| SECTION_SCALE_INDEX            | 34     |

### Subsystem

| Name                               | Number |
|------------------------------------|--------|
| SUBSYSTEM_UNKNOWN                  | 0      |
| SUBSYSTEM_NATIVE                   | 1      |
| SUBSYSTEM_WINDOWS_GUI              | 2      |
| SUBSYSTEM_WINDOWS_CUI              | 3      |
| SUBSYSTEM_OS2_CUI                  | 5      |
| SUBSYSTEM_POSIX_CUI                | 7      |
| SUBSYSTEM_NATIVE_WINDOWS           | 8      |
| SUBSYSTEM_WINDOWS_CE_GUI           | 9      |
| SUBSYSTEM_EFI_APPLICATION          | 10     |
| SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  | 11     |
| SUBSYSTEM_EFI_RUNTIME_DRIVER       | 12     |
| SUBSYSTEM_EFI_ROM_IMAGE            | 13     |
| SUBSYSTEM_XBOX                     | 14     |
| SUBSYSTEM_WINDOWS_BOOT_APPLICATION | 16     |
