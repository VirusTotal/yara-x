---
title: "elf"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "elf-module"
weight: 303
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `elf` module is very similar to the [pe]({{< ref "pe.md" >}}) module, but
for [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) files.
This module exposes most of the fields present in an ELF header.
Let's see some examples:

```yara
import "elf"

rule single_section {
    condition:
        elf.number_of_sections == 1
}

rule elf_64 {
    condition:
        elf.machine == elf.EM_X86_64
}
```

## Functions

### import_md5()

Returns the MD5 of the import table.

### telfhash()

Returns the TrendMicro's `telfhash` for the ELF file. This is a symbol hash for
ELF files, just like `imphash` is an imports hash for PE files. With `telfhash`,
you can cluster ELF files by similarity based on symbols.

Find more information in
TrendMicro's [whitepaper](https://documents.trendmicro.com/assets/pdf/TB_Telfhash-%20An%20Algorithm%20That%20Finds%20Similar%20Malicious%20ELF%20Files%20Used%20in%20Linux%20IoT%20Malware.pdf)
or
visit [https://github.com/trendmicro/telfhash](https://github.com/trendmicro/telfhash)
for tools other tools that compute the `telfhash`.

###### Example

```
import "elf"

rule FindByTelfhash {
    condition:
        elf.telfhash() == "t166a00284751084526486df8b5df5b2fccb3f511dbc188c37156f5e714a11bc5d71014d"
}
```

## Module structure

| Field                   | Type                      |
|-------------------------|---------------------------|
| type                    | [Type](#type)             |
| machine                 | [Machine](#machine)       |
| entry_point             | integer                   |
| sh_offset               | integer                   |
| sh_entry_size           | integer                   |
| ph_offset               | integer                   |
| ph_entry_size           | integer                   |
| number_of_sections      | integer                   |
| number_of_segments      | integer                   |
| symtab_entries          | integer                   |
| dynsym_entries          | integer                   |
| dynamic_section_entries | integer                   |
| sections                | [Section](#section) array |
| segments                | [Segment](#segment) array |
| symtab                  | [Sym](#sym) array         |
| dynsym                  | [Sym](#sym) array         |
| dynamic                 | [Dyn](#dyn) array         |

### Dyn

This is the structure of each item in the `dynamic` array.

| Field | Type                    |
|-------|-------------------------|
| type  | [DynType](#elf-DynType) |
| val   | integer                 |

### Section

This is the structure of each item in the `sections` array.

| Field   | Type                        |
|---------|-----------------------------|
| type    | [SectionType](#sectiontype) |
| flags   | integer                     |
| address | integer                     |
| size    | integer                     |
| offset  | integer                     |
| name    | string                      |

###### Example

```
import "elf"

rule DebugInfo {
    condition:
        for any section in elf.sections : (
           section.name == ".debug_info"
        )
}
```

### Segment

This is the structure of each item in the `segments` array.

| Field            | Type                        |
|------------------|-----------------------------|
| type             | [SegmentType](#segmenttype) |
| flags            | integer                     |
| offset           | integer                     |
| virtual_address  | integer                     |
| physical_address | integer                     |
| file_size        | integer                     |
| memory_size      | integer                     |
| alignment        | integer                     |

###### Example

```
import "elf"

rule NoLargeSegment {
    condition:
        for all segment in elf.segments : (
           segment.file_size < 0x100000
        )
}
```

### Sym

This is the structure of each item in the `symtab` and `dynsym` arrays.

| Field      | Type                            |
|------------|---------------------------------|
| name       | string                          |
| value      | integer                         |
| size       | integer                         |
| type       | [SymType](#symtype)             |
| bind       | [SymBind](#symbind)             |
| shndx      | integer                         |
| visibility | [SymVisibility](#symvisibility) |

###### Example

```
import "elf"

rule CrtStuff {
    condition:
        for any sym in elf.symtab : (
           sym.name == "crtstuff.c"
        )
}
```

### DynType

These are the possible values of the `type` field in the `Dyn` structure.

| Name            | Value      | Description                       |
|-----------------|------------|-----------------------------------|
| DT_NULL         | 0          | End of the dynamic entries        |
| DT_NEEDED       | 1          | Name of needed library            |
| DT_PLTRELSZ     | 2          | Size in bytes of PLT relocs       |
| DT_PLTGOT       | 3          | Processor defined value */        |
| DT_HASH         | 4          | Address of symbol hash table      |
| DT_STRTAB       | 5          | Address of string table           |
| DT_SYMTAB       | 6          | Address of symbol table           |
| DT_RELA         | 7          | Address of Rela relocs            |
| DT_RELASZ       | 8          | Total size of Rela relocs         |
| DT_RELAENT      | 9          | Size of one Rela reloc            |
| DT_STRSZ        | 10         | Size of string table              |
| DT_SYMENT       | 11         | Size of one symbol table entry    |
| DT_INIT         | 12         | Address of init function          |
| DT_FINI         | 13         | Address of termination function   |
| DT_SONAME       | 14         | Name of shared object             |
| DT_RPATH        | 15         | Library search path (deprecated)  |
| DT_SYMBOLIC     | 16         | Start symbol search here          |
| DT_REL          | 17         | Address of Rel relocs             |
| DT_RELSZ        | 18         | Total size of Rel relocs          |
| DT_RELENT       | 19         | Size of one Rel reloc             |
| DT_PLTREL       | 20         | Type of reloc in PLT              |
| DT_DEBUG        | 21         | For debugging; unspecified        |
| DT_TEXTREL      | 22         | Reloc might modify .text          |
| DT_JMPREL       | 23         | Address of PLT relocs             |
| DT_BIND_NOW     | 24         | Process relocations of object     |
| DT_INIT_ARRAY   | 25         | Array with addresses of init fct  |
| DT_FINI_ARRAY   | 26         | Array with addresses of fini fct  |
| DT_INIT_ARRAYSZ | 27         | Size in bytes of DT_INIT_ARRAY    |
| DT_FINI_ARRAYSZ | 28         | Size in bytes of DT_FINI_ARRAY    |
| DT_RUNPATH      | 29         | Library search path               |
| DT_FLAGS        | 30         | Flags for the object being loaded |
| DT_ENCODING     | 32         | Start of encoded range            |
| DT_LOOS         | 1610612749 |                                   |
| DT_HIOS         | 1879044096 |                                   |
| DT_VALRNGLO     | 1879047424 |                                   |
| DT_VALRNGHI     | 1879047679 |                                   |
| DT_ADDRRNGLO    | 1879047680 |                                   |
| DT_ADDRRNGHI    | 1879047935 |                                   |
| DT_VERSYM       | 1879048176 |                                   |
| DT_RELACOUNT    | 1879048185 |                                   |
| DT_RELCOUNT     | 1879048186 |                                   |
| DT_FLAGS_1      | 1879048187 |                                   |
| DT_VERDEF       | 1879048188 |                                   |
| DT_VERDEFNUM    | 1879048189 |                                   |
| DT_VERNEED      | 1879048190 |                                   |
| DT_VERNEEDNUM   | 1879048191 |                                   |
| DT_LOPROC       | 1879048192 |                                   |
| DT_HIPROC       | 2147483647 |                                   |

###### Example

```
import "elf"

rule HasSymTab {
    condition:
        for any dyn in elf.dynamic : (
           dyn.type == elf.DT_SYMTAB
        )
}
```

### Machine

These are the possible values of the `machine` field.

| Name           | Value  | Description               |
|----------------|--------|---------------------------|
| EM_NONE        | 0x0000 | No type                   |
| EM_M32         | 0x0001 | AT&amp;T WE 32100         |
| EM_SPARC       | 0x0002 | SPARC                     |
| EM_386         | 0x0003 | Intel 80386               |
| EM_68K         | 0x0004 | Motorola 68000            |
| EM_88K         | 0x0005 | Motorola 88000            |
| EM_IAMCU       | 0x0006 | Intel MCU                 |
| EM_860         | 0x0007 | Intel 80860               |
| EM_MIPS        | 0x0008 | MIPS I Architecture       |
| EM_S370        | 0x0009 | IBM S370                  |
| EM_MIPS_RS3_LE | 0x000A | MIPS RS3000 Little-endian |
| EM_PPC         | 0x0014 | PowerPC                   |
| EM_PPC64       | 0x0015 | 64-bit PowerPC            |
| EM_ARM         | 0x0028 | ARM                       |
| EM_X86_64      | 0x003E | AMD/Intel x86_64          |
| EM_AARCH64     | 0x00B7 | 64-bit ARM                |

###### Example

```
import "elf"

rule SparcELF {
    condition:
        elf.machine == elf.EM_SPARC
}
```

### SectionType

Each of the possible values for the `type` field in the `Section`
structure.

| Name           | Value | Description                       |
|----------------|-------|-----------------------------------|
| SHT_NULL       | 0     | Section header table entry unused |
| SHT_PROGBITS   | 1     | Program data                      |
| SHT_SYMTAB     | 2     | Symbol table                      |
| SHT_STRTAB     | 3     | String table                      |
| SHT_RELA       | 4     | Relocation entries with addends   |
| SHT_HASH       | 5     | Symbol hash table                 |
| SHT_DYNAMIC    | 6     | Dynamic linking information       |
| SHT_NOTE       | 7     | Notes                             |
| SHT_NOBITS     | 8     | Program space with no data (bss)  |
| SHT_REL        | 9     | Relocation entries, no addends    |
| SHT_SHLIB      | 10    | Reserved                          |
| SHT_DYNSYM     | 11    | Dynamic linker symbol table       |
| SHT_INIT_ARRAY | 14    | Array of constructors             |
| SHT_FINI_ARRAY | 15    | Array of destructors              |

###### Example

```
import "elf"

rule ElfWithRelocations {
    condition:
        for any section in elf.sections : (
           section.type == elf.SHT_REL or
           section.type == elf.SHT_RELA or
        )
}
```

### SegmentFlags

Possible flags in the `flags` fields of the `Segment` structure.

| Name | Value | Description           |
|------|-------|-----------------------|
| PF_X | 0x01  | Segment is executable |
| PF_W | 0x02  | Segment is writable   |
| PF_R | 0x04  | Segment is readable   |

###### Example

```
import "elf"

rule WritableExecutableSegment {
    condition:
        for any segment in elf.segments : (
           segment.flags & elf.PF_W != 0 and
           segment.flags & elf.PF_X != 0
        )
}
```

### SegmentType

| Name            | Value      | Description                               |
|-----------------|------------|-------------------------------------------|
| PT_NULL         | 0          | The array element is unused               |
| PT_LOAD         | 1          | Loadable segment                          |
| PT_DYNAMIC      | 2          | Segment contains dynamic linking info     |
| PT_INTERP       | 3          | Contains interpreter pathname             |
| PT_NOTE         | 4          | Location &amp; size of auxiliary info     |
| PT_SHLIB        | 5          | Reserved, unspecified semantics           |
| PT_PHDR         | 6          | Location and size of program header table |
| PT_TLS          | 7          | Thread-Local Storage                      |
| PT_GNU_EH_FRAME | 1685382480 |                                           |
| PT_GNU_STACK    | 1685382481 |                                           |
| PT_GNU_RELRO    | 1685382482 |                                           |
| PT_GNU_PROPERTY | 1685382483 |                                           |

### SymBind

| Name       | Value | Description   |
|------------|-------|---------------|
| STB_LOCAL  | 0     | Local symbol  |
| STB_GLOBAL | 1     | Global symbol |
| STB_WEAK   | 2     | Weak symbol   |

### SymType

| Name        | Value | Description                        |
|-------------|-------|------------------------------------|
| STT_NOTYPE  | 0     | Symbol type is unspecified         |
| STT_OBJECT  | 1     | Symbol is a data object            |
| STT_FUNC    | 2     | Symbol is a code object            |
| STT_SECTION | 3     | Symbol associated with a section   |
| STT_FILE    | 4     | Symbol&#39;s name is file name     |
| STT_COMMON  | 5     | Symbol is a common data object     |
| STT_TLS     | 6     | Symbol is thread-local data object |

### SymVisibility

| Name          | Value | Description                               |
|---------------|-------|-------------------------------------------|
| STV_DEFAULT   | 0     | Visibility by binding                     |
| STV_INTERNAL  | 1     | Reserved                                  |
| STV_HIDDEN    | 2     | Not visible to other components           |
| STV_PROTECTED | 3     | Visible in other but cannot be preempted. |

### Type

| Name      | Value  | Description        |
|-----------|--------|--------------------|
| ET_NONE   | 0x0000 | No type            |
| ET_REL    | 0x0001 | Relocatable        |
| ET_EXEC   | 0x0002 | Executable         |
| ET_DYN    | 0x0003 | Shared-Object-File |
| ET_CORE   | 0x0004 | Corefile           |
| ET_LOPROC | 0xFF00 | Processor-specific |
| ET_HIPROC | 0x00FF | Processor-specific |






