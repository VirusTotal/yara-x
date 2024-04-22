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
weight: 302
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
        pe.characteristics & pe.DLL
}

rule is_pe {
    condition:
        pe.is_pe
}
```

## Functions

## Module structure

| Field                                | Type                             | Description                                       |
|--------------------------------------|----------------------------------|---------------------------------------------------|
| is_pe                                | [bool](#bool)                    | True if the file is PE. Example: pe.is_pe.        |
| machine                              | [Machine](#machine)              | Machine type.                                     |
| subsystem                            | [Subsystem](#subsystem)          | Subsystem type.                                   |
| os_version                           | [Version](#version)              | OS version.                                       |
| subsystem_version                    | [Version](#version)              | Subsystem version.                                |
| image_version                        | [Version](#version)              |                                                   |
| linker_version                       | [Version](#version)              |                                                   |
| opthdr_magic                         | [OptionalMagic](#optionalmagic)  |                                                   |
| characteristics                      | integer                          |                                                   |
| dll_characteristics                  | integer                          |                                                   |
| timestamp                            | integer                          |                                                   |
| image_base                           | integer                          |                                                   |
| checksum                             | integer                          |                                                   |
| base_of_code                         | integer                          |                                                   |
| base_of_data                         | integer                          |                                                   |
| entry_point                          | integer                          | Entry point as a file offset.                     |
| entry_point_raw                      | integer                          | Entry point as it appears in the PE header (RVA). |
| dll_name                             | string                           |                                                   |
| export_timestamp                     | integer                          |                                                   |
| section_alignment                    | integer                          |                                                   |
| file_alignment                       | integer                          |                                                   |
| loader_flags                         | integer                          |                                                   |
| size_of_optional_header              | integer                          |                                                   |
| size_of_code                         | integer                          |                                                   |
| size_of_initialized_data             | integer                          |                                                   |
| size_of_uninitialized_data           | integer                          |                                                   |
| size_of_image                        | integer                          |                                                   |
| size_of_headers                      | integer                          |                                                   |
| size_of_stack_reserve                | integer                          |                                                   |
| size_of_stack_commit                 | integer                          |                                                   |
| size_of_heap_reserve                 | integer                          |                                                   |
| size_of_heap_commit                  | integer                          |                                                   |
| pointer_to_symbol_table              | integer                          |                                                   |
| win32_version_value                  | integer                          |                                                   |
| number_of_symbols                    | integer                          |                                                   |
| number_of_rva_and_sizes              | integer                          |                                                   |
| number_of_sections                   | integer                          |                                                   |
| number_of_imported_functions         | integer                          |                                                   |
| number_of_delayed_imported_functions | integer                          |                                                   |
| number_of_resources                  | integer                          |                                                   |
| number_of_version_infos              | integer                          |                                                   |
| number_of_imports                    | integer                          |                                                   |
| number_of_delayed_imports            | integer                          |                                                   |
| number_of_exports                    | integer                          |                                                   |
| number_of_signatures                 | integer                          |                                                   |
| version_info                         | dictionary                       |                                                   |
| version_info_list                    | array of [KeyValue](#keyvalue)   |                                                   |
| rich_signature                       | [RichSignature](#richSignature)  |                                                   |
| pdb_path                             | string                           |                                                   |
| sections                             | array of [Section](#section)     |                                                   |
| data_directories                     | array of [DirEntry](#dirEntry)   |                                                   |
| resource_timestamp                   | integer                          |                                                   |
| resource_version                     | [Version](#version)              | TODO: implement resource_version?                 |
| resources                            | array of [Resource](#resource)   |                                                   |
| import_details                       | array of [Import](#import)       |                                                   |
| delayed_import_details               | array of [Import](#import)       |                                                   |
| export_details                       | array of [Export](#export)       |                                                   |
| is_signed                            | bool                             |                                                   |
| signatures                           | array of [Signature](#signature) |                                                   |
| overlay                              | [Overlay](#overlay)              |                                                   |

### VersionInfo

| Field | Type              | Label    | Description |
|-------|-------------------|----------|-------------|
| key   | [string](#string) | optional |             |
| value | [string](#string) | optional |             |

### Certificate

| Field         | Type            | Label    | Description |
|---------------|-----------------|----------|-------------|
| issuer        | integer         | optional |             |
| subject       | integer         | optional |             |
| thumbprint    | integer         | optional |             |
| version       | [int64](#int64) | optional |             |
| algorithm     | integer         | optional |             |
| algorithm_oid | integer         | optional |             |
| serial        | integer         | optional |             |
| not_before    | [int64](#int64) | optional |             |
| not_after     | [int64](#int64) | optional |             |

<a name="pe-CounterSignature"></a>

### CounterSignature

| Field      | Type                           | Label    | Description |
|------------|--------------------------------|----------|-------------|
| verified   | [bool](#bool)                  | optional |             |
| sign_time  | [int64](#int64)                | optional |             |
| digest     | integer                        | optional |             |
| digest_alg | integer                        | optional |             |
| chain      | [Certificate](#pe-Certificate) | repeated |             |

<a name="pe-DirEntry"></a>

### DirEntry

| Field           | Type    | Label    | Description |
|-----------------|---------|----------|-------------|
| virtual_address | integer | required |             |
| size            | integer | required |             |

<a name="pe-Export"></a>

### Export

| Field        | Type    | Label    | Description |
|--------------|---------|----------|-------------|
| name         | integer | optional |             |
| ordinal      | integer | required |             |
| rva          | integer | required |             |
| offset       | integer | optional |             |
| forward_name | integer | optional |             |

<a name="pe-Function"></a>

### Function

| Field   | Type    | Label    | Description |
|---------|---------|----------|-------------|
| name    | integer | optional |             |
| ordinal | integer | optional |             |
| rva     | integer | required |             |

<a name="pe-Import"></a>

### Import

| Field               | Type                     | Label    | Description |
|---------------------|--------------------------|----------|-------------|
| library_name        | integer                  | required |             |
| number_of_functions | integer                  | required |             |
| functions           | [Function](#pe-Function) | repeated |             |

<a name="pe-KeyValue"></a>

### KeyValue

| Field | Type    | Label    | Description |
|-------|---------|----------|-------------|
| key   | integer | required |             |
| value | integer | required |             |

<a name="pe-Overlay"></a>

### Overlay

| Field  | Type    | Label    | Description |
|--------|---------|----------|-------------|
| offset | integer | required |             |
| size   | integer | required |             |

<a name="pe-PE"></a>

### PE.VersionInfoEntry

| Field | Type    | Label    | Description |
|-------|---------|----------|-------------|
| key   | integer | optional |             |
| value | integer | optional |             |

<a name="pe-Resource"></a>

### Resource

| Field           | Type                             | Label    | Description |
|-----------------|----------------------------------|----------|-------------|
| length          | integer                          | required |             |
| rva             | integer                          | required |             |
| offset          | integer                          | optional |             |
| type            | [ResourceType](#pe-ResourceType) | optional |             |
| id              | integer                          | optional |             |
| language        | integer                          | optional |             |
| type_string     | [bytes](#bytes)                  | optional |             |
| name_string     | [bytes](#bytes)                  | optional |             |
| language_string | [bytes](#bytes)                  | optional |             |

<a name="pe-RichSignature"></a>

### RichSignature

| Field      | Type                     | Label    | Description |
|------------|--------------------------|----------|-------------|
| offset     | integer                  | required |             |
| length     | integer                  | required |             |
| key        | integer                  | required |             |
| raw_data   | [bytes](#bytes)          | required |             |
| clear_data | [bytes](#bytes)          | required |             |
| tools      | [RichTool](#pe-RichTool) | repeated |             |

<a name="pe-RichTool"></a>

### RichTool

| Field   | Type    | Label    | Description |
|---------|---------|----------|-------------|
| toolid  | integer | required |             |
| version | integer | required |             |
| times   | integer | required |             |

<a name="pe-Section"></a>

### Section

| Field                   | Type            | Description |
|-------------------------|-----------------|-------------|
| name                    | [bytes](#bytes) |             |
| full_name               | [bytes](#bytes) |             | 
| characteristics         | integer         |             | 
| raw_data_size           | integer         |             | 
| raw_data_offset         | integer         |             | 
| virtual_address         | integer         |             | 
| virtual_size            | integer         |             | 
| pointer_to_relocations  | integer         |             | 
| pointer_to_line_numbers | integer         |             | 
| number_of_relocations   | integer         |             | 
| number_of_line_numbers  | integer         |             | 

<a name="pe-Signature"></a>

### Signature

| Field                       | Type                                     | Label    | Description |
|-----------------------------|------------------------------------------|----------|-------------|
| subject                     | integer                                  | optional |             |
| issuer                      | integer                                  | optional |             |
| thumbprint                  | integer                                  | optional |             |
| version                     | [int64](#int64)                          | optional |             |
| algorithm                   | integer                                  | optional |             |
| algorithm_oid               | integer                                  | optional |             |
| serial                      | integer                                  | optional |             |
| not_before                  | [int64](#int64)                          | optional |             |
| not_after                   | [int64](#int64)                          | optional |             |
| verified                    | [bool](#bool)                            | optional |             |
| digest_alg                  | integer                                  | optional |             |
| digest                      | integer                                  | optional |             |
| file_digest                 | integer                                  | optional |             |
| number_of_certificates      | integer                                  | optional |             |
| number_of_countersignatures | integer                                  | optional |             |
| signer_info                 | [SignerInfo](#pe-SignerInfo)             | optional |             |
| certificates                | [Certificate](#pe-Certificate)           | repeated |             |
| countersignatures           | [CounterSignature](#pe-CounterSignature) | repeated |             |

<a name="pe-SignerInfo"></a>

### SignerInfo

| Field        | Type                           | Label    | Description |
|--------------|--------------------------------|----------|-------------|
| program_name | integer                        | optional |             |
| digest       | integer                        | optional |             |
| digest_alg   | integer                        | optional |             |
| chain        | [Certificate](#pe-Certificate) | repeated |             |

<a name="pe-Version"></a>

### Version

| Field | Type    | Label    | Description |
|-------|---------|----------|-------------|
| major | integer | required |             |
| minor | integer | required |             |

<a name="pe-Characteristics"></a>

### Characteristics

| Name                    | Number | Description                                                      |
|-------------------------|--------|------------------------------------------------------------------|
| RELOCS_STRIPPED         | 1      | Relocation info stripped from file.                              |
| EXECUTABLE_IMAGE        | 2      | File is executable (i.e. no unresolved external references).     |
| LINE_NUMS_STRIPPED      | 4      | Line numbers stripped from file.                                 |
| LOCAL_SYMS_STRIPPED     | 8      | Local symbols stripped from file.                                |
| AGGRESIVE_WS_TRIM       | 16     | Aggressively trim working set                                    |
| LARGE_ADDRESS_AWARE     | 32     | App can handle &gt;2gb addresses                                 |
| BYTES_REVERSED_LO       | 128    | Bytes of machine word are reversed.                              |
| MACHINE_32BIT           | 256    | 32 bit word machine.                                             |
| DEBUG_STRIPPED          | 512    | Debugging info stripped from file in .DBG file                   |
| REMOVABLE_RUN_FROM_SWAP | 1024   | If Image is on removable media, copy and run from the swap file. |
| NET_RUN_FROM_SWAP       | 2048   | If Image is on Net, copy and run from the swap file.             |
| SYSTEM                  | 4096   | System File.                                                     |
| DLL                     | 8192   | File is a DLL.s                                                  |
| UP_SYSTEM_ONLY          | 16384  | File should only be run on a UP machine                          |
| BYTES_REVERSED_HI       | 32768  | Bytes of machine word are reversed.                              |

<a name="pe-DirectoryEntry"></a>

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

<a name="pe-DllCharacteristics"></a>

### DllCharacteristics

| Name                  | Number |
|-----------------------|--------|
| HIGH_ENTROPY_VA       | 32     |
| DYNAMIC_BASE          | 64     |
| FORCE_INTEGRITY       | 128    |
| NX_COMPAT             | 256    |
| NO_ISOLATION          | 512    |
| NO_SEH                | 1024   |
| NO_BIND               | 2048   |
| APPCONTAINER          | 4096   |
| WDM_DRIVER            | 8192   |
| GUARD_CF              | 16384  |
| TERMINAL_SERVER_AWARE | 32768  |

<a name="pe-ImportFlags"></a>

### ImportFlags

| Name            | Number |
|-----------------|--------|
| IMPORT_STANDARD | 1      |
| IMPORT_DELAYED  | 2      |
| IMPORT_ANY      | 3      |

<a name="pe-Machine"></a>

### Machine

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

<a name="pe-OptionalMagic"></a>

### OptionalMagic

| Name                          | Number |
|-------------------------------|--------|
| IMAGE_NT_OPTIONAL_HDR32_MAGIC | 267    |
| IMAGE_NT_OPTIONAL_HDR64_MAGIC | 523    |
| IMAGE_ROM_OPTIONAL_HDR_MAGIC  | 263    |

<a name="pe-ResourceType"></a>

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

<a name="pe-SectionCharacteristics"></a>

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

<a name="pe-Subsystem"></a>

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
