---
title: "macho"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "macho-module"
weight: 310
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `macho` module allows you to create more fine-grained rules for [Mach-O](https://en.wikipedia.org/wiki/Mach-O) files by using attributes and features of the Mach-O file format. This module exposes most of the fields present in a Mach-O header and provides functions which can be used to write more expressive and targeted rules. Let's see some examples:

```yara
import "macho"

rule cpu_type {
  condition:
    macho.cputype == macho.CPU_TYPE_X86_64
}

rule frameworks_rpath {
  condition:
    macho.has_rpath("@loader_path/../Frameworks")
}

rule dylib_hash {
  condition:
    macho.dylib_hash() == "c92070ad210458d5b3e8f048b1578e6d"
}
```

-------

## Functions

### file_index_for_arch(type_arg)

Returns the the index of a Mach-O file within a fat binary based on CPU type.

#### Example

```yara
import "macho"

rule file_index_example {
  condition:
    macho.file_index_for_arch(0x00000008) == 0
}
```

### file_index_for_arch(type_arg, subtype_arg)

Returns the index of a Mach-O file within a fat binary based on both CPU type and subtype.

#### Example

```yara
import "macho"

rule file_index_example_sub {
  condition:
    macho.file_index_for_arch(0x00000008, 0x00000004) == 0
}
```

### entry_point_for_arch(type_arg)

Returns the real entry point offset for a specific CPU type within a fat Mach-O binary.

#### Example

```yara
import "macho"

rule entrypoint_example {
  condition:
    macho.entry_point_for_arch(0x01000007) == 0x00004EE0
}
```

### entry_point_for_arch(type_arg, subtype_arg))

Returns the real entry point offset for a specific CPU type and subtype within a fat Mach-O binary.

#### Example

```yara
import "macho"

rule entrypoint_example_sub {
  condition:
    macho.entry_point_for_arch(0x00000007, 0x00000003) == 0x00001EE0
}
```

### has_entitlement(entitlement)

Returns true if the Mach-O parsed entitlements contain `entitlement`
- `entitlement` is case-insensitive.
  
#### Example

```yara
import "macho"

rule has_entitlement_example {
  condition:
    macho.has_entitlement("com.apple.security.network.client")
}
```

### has_dylib(dylib_name)

Returns true if the Mach-O parsed dylibs contain `dylib_name`
- `dylib_name` is case-insensitive.

#### Example

```yara
import "macho"

rule has_dylib_example {
  condition:
    macho.has_dylib("/usr/lib/libSystem.B.dylib")
}
```

### has_rpath(rpath)

Returns true if the Mach-O parsed rpaths contain `rpath`
- `rpath` is case-insensitive.

#### Example

```yara
import "macho"

rule has_rpath_example {
  condition:
    macho.has_rpath("@loader_path/../Frameworks")
}
```

### has_import(import)

Returns true if the Mach-O parsed imports contain `import`
- `import` is case-insensitive.

#### Example

```yara
import "macho"

rule has_import_example {
  condition:
    macho.has_import("_NSEventTrackingRunLoopMode")
}
```

### has_export(export)

Returns true if the Mach-O parsed exports contain `export`
- `export` is case-insensitive.

#### Example

```yara
import "macho"

rule has_export_example {
  condition:
    macho.has_export("_main")
}
```

### dylib_hash()

Returns an MD5 hash of the dylibs designated in the Mach-O binary.

{{< callout title="Notice">}}

The returned hash string is always in lowercase.

{{< /callout >}}

#### Example

```yara
import "macho"

rule dylib_hash_example {
  condition:
    macho.dylib_hash() == "c92070ad210458d5b3e8f048b1578e6d"
}
```

### entitlement_hash()

Returns an MD5 hash of the entitlements designated in the Mach-O binary.

{{< callout title="Notice">}}

The returned hash string is always in lowercase.

{{< /callout >}}

#### Example

```yara
import "macho"

rule entitlement_hash_example {
  condition:
    macho.entitlement_hash() == "cc9486efb0ce73ba411715273658da80"
}
```

### export_hash()

Returns an MD5 hash of the exports designated in the Mach-O binary.

{{< callout title="Notice">}}

The returned hash string is always in lowercase.

{{< /callout >}}

#### Example

```yara
import "macho"

rule export_hash_example {
  condition:
    macho.export_hash() == "6bfc6e935c71039e6e6abf097830dceb"
}
```

### import_hash()

Returns an MD5 hash of the imports designated in the Mach-O binary.

{{< callout title="Notice">}}

The returned hash string is always in lowercase.

{{< /callout >}}

#### Example

```yara
import "macho"

rule import_hash_example {
  condition:
    macho.import_hash() == "35ea3b116d319851d93e26f7392e876e"
}
```

------

### Module structure

| Field               | Type                          |
| ------------------- | ----------------------------- |
| magic               | integer                       |
| cputype             | integer                       |
| cpusubtype          | integer                       |
| filetype            | integer                       |
| ncmds               | integer                       |
| sizeofcmds          | integer                       |
| flags               | integer                       |
| reserved            | integer                       |
| number_of_segments  | integer                       |
| dynamic_linker      | string                        |
| entry_point         | integer                       |
| stack_size          | integer                       |
| source_version      | string                        |
| symtab              | [Symtab](#symtab)             |
| dysymtab            | [Dysymtab](#dysymtab)         |
| code_signature_data | [LinkedItData](#linkeditdata) |
| segments            | [Segment](#segment) array     |
| dylibs              | [Dylib](#dylib) array         |
| dyld_info           | [DyldInfo](#dyldinfo)         |
| rpaths              | string array                  |
| entitlements        | string array                  |
| certificates        | [Certificates](#certificates) |
| uuid                | string                        |
| build_version       | [BuildVersion](#buildversion) |
| min_version         | [MinVersion](#minversion)     |
| exports             | string array                  |
| fat_magic           | integer                       |
| nfat_arch           | integer                       |
| fat_arch            | [FatArch](#fatarch) array     |
| file                | [File](#file) array           |

### BuildTool

| Field   | Type    |
| ------- | ------- |
| tool    | integer |
| version | string  |

### BuildVersion

| Field    | Type                          |
| -------- | ----------------------------- |
| platform | integer                       |
| minos    | string                        |
| sdk      | string                        |
| ntools   | integer                       |
| tools    | [BuildTool](#buildtool) array |

<a name="macho-Certificates"></a>

### Certificates

| Field        | Type         |
| ------------ | ------------ |
| common_names | string array |
| signer_names | string array |

### DyldInfo

| Field          | Type    |
| -------------- | ------- |
| rebase_off     | integer |
| rebase_size    | integer |
| bind_off       | integer |
| bind_size      | integer |
| weak_bind_off  | integer |
| weak_bind_size | integer |
| lazy_bind_off  | integer |
| lazy_bind_size | integer |
| export_off     | integer |
| export_size    | integer |

### Dylib

| Field                 | Type    |
| --------------------- | ------- |
| name                  | string  |
| timestamp             | integer |
| compatibility_version | string  |
| current_version       | string  |

### Dysymtab

| Field          | Type    |
| -------------- | ------- |
| ilocalsym      | integer |
| nlocalsym      | integer |
| iextdefsym     | integer |
| nextdefsym     | integer |
| iundefsym      | integer |
| nundefsym      | integer |
| tocoff         | integer |
| ntoc           | integer |
| modtaboff      | integer |
| nmodtab        | integer |
| extrefsymoff   | integer |
| nextrefsyms    | integer |
| indirectsymoff | integer |
| nindirectsyms  | integer |
| extreloff      | integer |
| nextrel        | integer |
| locreloff      | integer |
| nlocrel        | integer |

### FatArch

| Field      | Type    |
| ---------- | ------- |
| cputype    | integer |
| cpusubtype | integer |
| offset     | integer |
| size       | integer |
| align      | integer |
| reserved   | integer |

### File

| Field               | Type                          |
| ------------------- | ----------------------------- |
| magic               | integer                       |
| cputype             | integer                       |
| cpusubtype          | integer                       |
| filetype            | integer                       |
| ncmds               | integer                       |
| sizeofcmds          | integer                       |
| flags               | integer                       |
| reserved            | integer                       |
| number_of_segments  | integer                       |
| dynamic_linker      | string                        |
| entry_point         | integer                       |
| stack_size          | integer                       |
| source_version      | string                        |
| segments            | [Segment](#segment) array     |
| dylibs              | [Dylib](#dylib) array         |
| rpaths              | string array                  |
| entitlements        | string array                  |
| symtab              | [Symtab](#symtab)             |
| dysymtab            | [Dysymtab](#dysymtab)         |
| dyld_info           | [DyldInfo](#dyldInfo)         |
| code_signature_data | [LinkedItData](#linkeditdata) |
| certificates        | [Certificates](#certificates) |
| uuid                | string                        |
| build_version       | [BuildVersion](#buildversion) |
| min_version         | [MinVersion](#minversion)     |

### LinkedItData

| Field    | Type    |
| -------- | ------- |
| dataoff  | integer |
| datasize | integer |

### MinVersion

| Field   | Type                        |
| ------- | --------------------------- |
| device  | [DEVICE_TYPE](#device_type) |
| version | string                      |
| sdk     | string                      |

### Section

| Field     | Type    |
| --------- | ------- |
| segname   | string  |
| sectname  | string  |
| addr      | integer |
| size      | integer |
| offset    | integer |
| align     | integer |
| reloff    | integer |
| nreloc    | integer |
| flags     | integer |
| reserved1 | integer |
| reserved2 | integer |
| reserved3 | integer |

### Segment

| Field    | Type                      |
| -------- | ------------------------- |
| segname  | string                    |
| vmaddr   | integer                   |
| vmsize   | integer                   |
| fileoff  | integer                   |
| filesize | integer                   |
| maxprot  | integer                   |
| initprot | integer                   |
| nsects   | integer                   |
| flags    | integer                   |
| sections | [Section](#section) array |

### Symtab

| Field   | Type         |
| ------- | ------------ |
| symoff  | integer      |
| nsyms   | integer      |
| stroff  | integer      |
| strsize | integer      |
| entries | string array |

### CPU_ARM_64_SUBTYPE

| Name                  | Number |
| --------------------- | ------ |
| CPU_SUBTYPE_ARM_V5TEJ | 7      |
| CPU_SUBTYPE_ARM64_ALL | 0      |

### CPU_ARM_SUBTYPE

| Name                   | Number |
| ---------------------- | ------ |
| CPU_SUBTYPE_ARM_ALL    | 0      |
| CPU_SUBTYPE_ARM_V4T    | 5      |
| CPU_SUBTYPE_ARM_V6     | 6      |
| CPU_SUBTYPE_ARM_V5     | 7      |
| CPU_SUBTYPE_ARM_XSCALE | 8      |
| CPU_SUBTYPE_ARM_V7     | 9      |
| CPU_SUBTYPE_ARM_V7F    | 10     |
| CPU_SUBTYPE_ARM_V7S    | 11     |
| CPU_SUBTYPE_ARM_V7K    | 12     |
| CPU_SUBTYPE_ARM_V6M    | 14     |
| CPU_SUBTYPE_ARM_V7M    | 15     |
| CPU_SUBTYPE_ARM_V7EM   | 16     |

### CPU_I386_SUBTYPE

| Name                 | Number |
| -------------------- | ------ |
| CPU_SUBTYPE_I386_ALL | 3      |

### CPU_I386_TYPE

| Name          | Number |
| ------------- | ------ |
| CPU_TYPE_I386 | 7      |

### CPU_INTEL_PENTIUM_SUBTYPE

| Name                       | Number |
| -------------------------- | ------ |
| CPU_SUBTYPE_PENT           | 5      |
| CPU_SUBTYPE_PENTPRO        | 22     |
| CPU_SUBTYPE_PENTII_M3      | 54     |
| CPU_SUBTYPE_PENTII_M5      | 86     |
| CPU_SUBTYPE_PENTIUM_3      | 8      |
| CPU_SUBTYPE_PENTIUM_3_M    | 24     |
| CPU_SUBTYPE_PENTIUM_3_XEON | 40     |
| CPU_SUBTYPE_PENTIUM_M      | 9      |
| CPU_SUBTYPE_PENTIUM_4      | 10     |
| CPU_SUBTYPE_PENTIUM_4_M    | 26     |

### CPU_INTEL_SUBTYPE

| Name                        | Number |
| --------------------------- | ------ |
| CPU_SUBTYPE_INTEL_MODEL_ALL | 0      |
| CPU_SUBTYPE_386             | 3      |
| CPU_SUBTYPE_486             | 4      |
| CPU_SUBTYPE_486SX           | 132    |
| CPU_SUBTYPE_586             | 5      |
| CPU_SUBTYPE_CELERON         | 103    |
| CPU_SUBTYPE_CELERON_MOBILE  | 119    |
| CPU_SUBTYPE_ITANIUM         | 11     |
| CPU_SUBTYPE_ITANIUM_2       | 27     |
| CPU_SUBTYPE_XEON            | 12     |
| CPU_SUBTYPE_XEON_MP         | 28     |

### CPU_MC_SUBTYPE

| Name                     | Number |
| ------------------------ | ------ |
| CPU_SUBTYPE_MC980000_ALL | 0      |
| CPU_SUBTYPE_MC98601      | 1      |

### CPU_POWERPC_SUBTYPE

| Name                      | Number |
| ------------------------- | ------ |
| CPU_SUBTYPE_POWERPC_ALL   | 0      |
| CPU_SUBTYPE_POWERPC_601   | 1      |
| CPU_SUBTYPE_POWERPC_602   | 2      |
| CPU_SUBTYPE_POWERPC_603   | 3      |
| CPU_SUBTYPE_POWERPC_603e  | 4      |
| CPU_SUBTYPE_POWERPC_603ev | 5      |
| CPU_SUBTYPE_POWERPC_604   | 6      |
| CPU_SUBTYPE_POWERPC_604e  | 7      |
| CPU_SUBTYPE_POWERPC_620   | 8      |
| CPU_SUBTYPE_POWERPC_750   | 9      |
| CPU_SUBTYPE_POWERPC_7400  | 10     |
| CPU_SUBTYPE_POWERPC_7450  | 11     |
| CPU_SUBTYPE_POWERPC_970   | 100    |

### CPU_SPARC_SUBTYPE

| Name                  | Number |
| --------------------- | ------ |
| CPU_SUBTYPE_SPARC_ALL | 0      |

### CPU_TYPE

| Name               | Number   |
| ------------------ | -------- |
| CPU_TYPE_MC680X0   | 6        |
| CPU_TYPE_X86       | 7        |
| CPU_TYPE_X86_64    | 16777223 |
| CPU_TYPE_MIPS      | 8        |
| CPU_TYPE_MC98000   | 10       |
| CPU_TYPE_ARM       | 12       |
| CPU_TYPE_ARM64     | 16777228 |
| CPU_TYPE_MC88000   | 13       |
| CPU_TYPE_SPARC     | 14       |
| CPU_TYPE_POWERPC   | 18       |
| CPU_TYPE_POWERPC64 | 16777234 |

### CPU_X86_SUBTYPE

| Name                   | Number |
| ---------------------- | ------ |
| CPU_SUBTYPE_X86_64_ALL | 3      |

### DEVICE_TYPE

| Name     | Number |
| -------- | ------ |
| MACOSX   | 36     |
| IPHONEOS | 37     |
| TVOS     | 47     |
| WATCHOS  | 48     |

### FAT_HEADER

| Name         | Number |
| ------------ | ------ |
| FAT_MAGIC    | 0      |
| FAT_CIGAM    | 1      |
| FAT_MAGIC_64 | 2      |
| FAT_CIGAM_64 | 3      |

### FILE_FLAG

| Name                       | Number   |
| -------------------------- | -------- |
| MH_NOUNDEFS                | 1        |
| MH_INCRLINK                | 2        |
| MH_DYLDLINK                | 4        |
| MH_BINDATLOAD              | 8        |
| MH_PREBOUND                | 16       |
| MH_SPLIT_SEGS              | 32       |
| MH_LAZY_INIT               | 64       |
| MH_TWOLEVEL                | 128      |
| MH_FORCE_FLAT              | 256      |
| MH_NOMULTIDEFS             | 512      |
| MH_NOFIXPREBINDING         | 1024     |
| MH_PREBINDABLE             | 2048     |
| MH_ALLMODSBOUND            | 4096     |
| MH_SUBSECTIONS_VIA_SYMBOLS | 8192     |
| MH_CANONICAL               | 16384    |
| MH_WEAK_DEFINES            | 32768    |
| MH_BINDS_TO_WEAK           | 65536    |
| MH_ALLOW_STACK_EXECUTION   | 131072   |
| MH_ROOT_SAFE               | 262144   |
| MH_SETUID_SAFE             | 524288   |
| MH_NO_REEXPORTED_DYLIBS    | 1048576  |
| MH_PIE                     | 2097152  |
| MH_DEAD_STRIPPABLE_DYLIB   | 4194304  |
| MH_HAS_TLV_DESCRIPTORS     | 8388608  |
| MH_NO_HEAP_EXECUTION       | 16777216 |
| MH_APP_EXTENSION_SAFE      | 33554432 |

### FILE_TYPE

| Name           | Number |
| -------------- | ------ |
| MH_OBJECT      | 1      |
| MH_EXECUTE     | 2      |
| MH_FVMLIB      | 3      |
| MH_CORE        | 4      |
| MH_PRELOAD     | 5      |
| MH_DYLIB       | 6      |
| MH_DYLINKER    | 7      |
| MH_BUNDLE      | 8      |
| MH_DYLIB_STUB  | 9      |
| MH_DSYM        | 10     |
| MH_KEXT_BUNDLE | 11     |

### HEADER

| Name        | Number |
| ----------- | ------ |
| MH_MAGIC    | 0      |
| MH_CIGAM    | 1      |
| MH_MAGIC_64 | 2      |
| MH_CIGAM_64 | 3      |

### MASK_64BIT

| Name              | Number   |
| ----------------- | -------- |
| CPU_ARCH_ABI64    | 16777216 |
| CPU_SUBTYPE_LIB64 | 0        |

### SECTION_ATTRIBUTES

| Name                       | Number     |
| -------------------------- | ---------- |
| S_ATTR_PURE_INSTRUCTIONS   | 0          |
| S_ATTR_NO_TOC              | 1073741824 |
| S_ATTR_STRIP_STATIC_SYMS   | 536870912  |
| S_ATTR_NO_DEAD_STRIP       | 268435456  |
| S_ATTR_LIVE_SUPPORT        | 134217728  |
| S_ATTR_SELF_MODIFYING_CODE | 67108864   |
| S_ATTR_DEBUG               | 33554432   |
| S_ATTR_SOME_INSTRUCTIONS   | 1024       |
| S_ATTR_EXT_RELOC           | 512        |
| S_ATTR_LOC_RELOC           | 256        |

### SECTION_TYPE

| Name                                  | Number |
| ------------------------------------- | ------ |
| S_REGULAR                             | 0      |
| S_ZEROFILL                            | 1      |
| S_CSTRING_LITERALS                    | 2      |
| S_4BYTE_LITERALS                      | 3      |
| S_8BYTE_LITERALS                      | 4      |
| S_LITERAL_POINTERS                    | 5      |
| S_NON_LAZY_SYMBOL_POINTERS            | 6      |
| S_LAZY_SYMBOL_POINTERS                | 7      |
| S_SYMBOL_STUBS                        | 8      |
| S_MOD_INIT_FUNC_POINTERS              | 9      |
| S_MOD_TERM_FUNC_POINTERS              | 10     |
| S_COALESCED                           | 11     |
| S_GB_ZEROFILL                         | 12     |
| S_INTERPOSING                         | 13     |
| S_16BYTE_LITERALS                     | 14     |
| S_DTRACE_DOF                          | 15     |
| S_LAZY_DYLIB_SYMBOL_POINTERS          | 16     |
| S_THREAD_LOCAL_REGULAR                | 17     |
| S_THREAD_LOCAL_ZEROFILL               | 18     |
| S_THREAD_LOCAL_VARIABLES              | 19     |
| S_THREAD_LOCAL_VARIABLE_POINTERS      | 20     |
| S_THREAD_LOCAL_INIT_FUNCTION_POINTERS | 21     |

### SEGMENT_FLAG

| Name                   | Number |
| ---------------------- | ------ |
| SG_HIGHVM              | 1      |
| SG_FVMLIB              | 2      |
| SG_NORELOC             | 4      |
| SG_PROTECTED_VERSION_1 | 8      |

