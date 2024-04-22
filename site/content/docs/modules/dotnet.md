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

rule GetHashCodeMethod {
    condition:
        for any class in dotnet.classes : (
           for any method in class.methods : (
                method.name == "GetHashCode" and
                method.visibility == "public"
           )
        )
}

rule BlopStream {
    condition:
        for any stream in dotnet.streams :( 
            stream.name == "#Blop"
        )
}
```

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
| guids                        | array of string                      |
| constants                    | array of string                      |
| assembly                     | [Assembly](#assembly)                |
| assembly_refs                | array of [AssemblyRef](#assemblyref) |
| resources                    | array of [Resource](#resource)       |
| classes                      | array of [Class](#class)             |
| field_offsets                | array of integer                     |
| user_strings                 | array of string                      |
| modulerefs                   | array of string                      |

### Assembly

This is the structure in the `assembly` field, which contains general
information about the .NET assembly.

| Field   | Type                |
|---------|---------------------|
| name    | string              |
| culture | string              |
| version | [Version](#version) |

###### Example

```
import "dotnet"

rule RDMCOLib {
    condition:
        dotnet.assembly.name == "Interop.RDMCOLib"
}
```

### AssemblyRef

This is the structure of each item in the `assembly_refs` array.

| Field               | Type                |
|---------------------|---------------------|
| name                | string              |
| public_key_or_token | string              |
| version             | [Version](#version) |

###### Example

```
import "dotnet"

rule WindowsFirewallHelper {
    condition:
        for any ref in dotnet.assembly_refs : (
            ref.name == "WindowsFirewallHelper" and
            ref.version.major == 4
        )
}
```

### Class

This is the structure of each item in the `classes` array.

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

###### Example

```
import "dotnet"

rule DebugInfoInPDBAttribute {
    condition:
        for any class in dotnet.classes : (
           class.fullname == "Microsoft.VisualC.DebugInfoInPDBAttribute"
        )
}
```

### Method

This is the structure of each item in the `methods` array within each Class.

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

###### Example

```
import "dotnet"

rule GetHashCode {
    condition:
        for any class in dotnet.classes : (
           for any method in class.methods : (
                method.name == "GetHashCode" and
                method.visibility == "public"
           )
        )
}
```

### Param

This is the structure of each item in the `parametes` array within each Method.

| Field | Type   |
|-------|--------|
| name  | string |
| type  | string |

###### Example

```
import "dotnet"

rule FreezeEvents {
    condition:
        for any class in dotnet.classes : (
           for any method in class.methods : (
                for any param in method.parameters : (
                    param.name == "pFreezeEvents" 
                )
           )
        )
}
```

### Resource

This is the structure of each item in the `resources` array.

| Field  | Type    |
|--------|---------|
| offset | integer |
| length | integer |
| name   | string  |

###### Example

```
import "dotnet"

rule TurboPing {
    condition:
        for any res in dotnet.resources : (
           res.name startswith "TurboPing"
        )
}
```

### Stream

This is the structure of each item in the `streams` array.

| Field  | Type    |
|--------|---------|
| name   | string  |
| offset | integer |
| size   | integer |

###### Example

```
import "dotnet"

rule DarksProtector {
    condition:
        for any stream in dotnet.streams : (
           stream.name == "DarksProtector"
        )
}
```

### Version

| Field           | Type    |
|-----------------|---------|
| major           | integer |
| minor           | integer |
| build_number    | integer |
| revision_number | integer |

