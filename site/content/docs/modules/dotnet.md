---
title: "dotnet"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "dotnet-module"
weight: 305
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `dotnet` module allows you to create more fine-grained rules for .NET files
by using attributes and features of the .NET file format. Let's see some
examples:

```
import "dotnet"

rule not_exactly_five_streams {
    condition:
        dotnet.number_of_streams != 5
}

rule blop_stream {
    condition:
        for any i in (0..dotnet.number_of_streams - 1) :( 
            dotnet.streams[i].name == "#Blop"
        )
}
```

## Functions

## Module structure

| Field                        | Type                                 |
|------------------------------|--------------------------------------|
| is_dotnet                    | bool                                 |
| module_name                  | string                               |
| version                      | string                               |
| number_of_streams            | integer                              |
| number_of_guids              | integer                              |
| number_of_resources          | integer                              |
| number_of_generic_parameters | integer                              |
| number_of_classes            | integer                              |
| number_of_assembly_refs      | integer                              |
| number_of_modulerefs         | integer                              |
| number_of_user_strings       | integer                              |
| number_of_constants          | integer                              |
| number_of_field_offsets      | integer                              |
| typelib                      | string                               |
| streams                      | array of [Stream](#stream)           |
| guids                        | string                               |
| constants                    | array of string                      |
| assembly                     | [Assembly](#assembly)                |
| assembly_refs                | array of [AssemblyRef](#assemblyref) |
| resources                    | array of [Resource](#resource)       |
| classes                      | array of [Class](#class)             |
| field_offsets                | integer                              |
| user_strings                 | array of string                      |
| modulerefs                   | string                               |

### Assembly

| Field   | Type                |
|---------|---------------------|
| name    | string              |
| culture | string              |
| version | [Version](#version) |

### AssemblyRef

| Field               | Type                |
|---------------------|---------------------|
| name                | string              |
| public_key_or_token | string              |
| version             | [Version](#version) |

### Class

| Field                        | Type                       |
|------------------------------|----------------------------|
| fullname                     | string                     |
| name                         | string                     |
| namespace                    | string                     |
| visibility                   | string                     |
| type                         | string                     |
| abstract                     | bool                       |
| sealed                       | bool                       |
| number_of_base_types         | integer                    |
| number_of_generic_parameters | integer                    |
| number_of_methods            | integer                    |
| base_types                   | array of string            |
| generic_parameters           | array of string            |
| methods                      | array of [Method](#method) |

### Method

| Field                        | Type                     |
|------------------------------|--------------------------|
| name                         | string                   |
| visibility                   | string                   |
| abstract                     | bool                     |
| static                       | bool                     |
| virtual                      | bool                     |
| final                        | bool                     |
| return_type                  | string                   |
| number_of_generic_parameters | integer                  |
| number_of_parameters         | integer                  |
| generic_parameters           | array of string          |
| parameters                   | array of [Param](#param) |

### Param

| Field | Type   |
|-------|--------|
| name  | string |
| type  | string |

### Resource

| Field  | Type    |
|--------|---------|
| offset | integer |
| length | integer |
| name   | string  |

### Stream

| Field  | Type    |
|--------|---------|
| name   | string  |
| offset | integer |
| size   | integer |

### Version

| Field           | Type    |
|-----------------|---------|
| major           | integer |
| minor           | integer |
| build_number    | integer |
| revision_number | integer |

