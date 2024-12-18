---
title: "Leveraging the Mach-O module in YARA-X"
description: "YARA-X now features a macho module for parsing and extracting information from Mach-O binaries which aids in writing rules and detections."
summary: ""
date: 2024-12-18T00:00:00+01:00
lastmod: 2024-12-18T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Jacob Latonis" ]
pinned: false
homepage: false
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

# Introduction
Detecting things in Mach-O binaries used to be quite an effort in the original YARA; it would involve magic byte validation, guessing offsests, counting occurrences, and a whole lot more. 

With the advent of YARA-X, the new and improved Mach-O module can be leveraged in various ways. This blog post will detail particular use-cases and show examples for those and more.

If you're interested in seeing a more in-depth look at some of the features mentioned below, you can find a talk, given by [Jacob Latonis](https://x.com/jacoblatonis) and [Greg Lesnewich](https://x.com/greglesnewich) which breaks down the motivations behind the Mach-O module in YARA-X and features examples of how it can be utilized, [here](https://youtu.be/Nm0zLW8RhXM?t=6470).

# Usage

## Importing the `macho` module
To begin using the `macho` module inside of a YARA rule, add the following at the top of your rule like so:

```
import "macho"

rule example {
    condition:
        true
}
```

## Myriad structures inside a Mach-O binary
A Mach-O binary can feature a lot of different information and structures. To see all of what YARA-X and the `macho` module can potentially parse, you can see everything documented in the [`macho` documentation](https://virustotal.github.io/yara-x/docs/modules/macho/) for YARA-X.

This section will cover commonly used structures for detections in YARA rules.

### Symbol Table
If you want to detect around something in the symbol table, we can leverage the `macho.symtab` structure, where each string is located in `entries`.

```yara
import "macho"

rule swift_bin {
    condition: 
        for any symbol in macho.symtab.entries: (
            symbol == "_swift_getObjCClassMetadata"
        )
}
```

### Imports
The `macho` module has multiple ways to explore imports in a Mach-O binary.

To iterate over the imports defined via load commands in the Mach-O binary, one can use the array of imports located at `macho.imports`:

```yara
import "macho"

rule macho_imports {
    condition:
        for any i in macho.imports: (
            i contains "_harmony_"
        )
}
```

Use `has_import` to detect whether an import is present in a given binary.

```yara
import "macho"

rule macho_imports {
    condition:
        macho.has_import("_NSEventTrackingRunLoopMode")
}
```

### Exports
Exported symbols from the Mach-O binary are parsed in YARA-X and can be used queried against and enumerated.

To iterate over the exports found in a Mach-O binary, the `macho` module contains the list of exports as a string found at `macho.exports`.

```yara
import "macho"

rule macho_exports {
    condition:
        for any e in macho.exports: (
            e contains "execute_header"
        )
}
```

To check if a Mach-O binary contains a specific export, one can leverage the `has_export()` function like so:

```yara
import "macho"

rule macho_exports_query {
    condition:
        macho.has_export("suspicious_export_identifier")
}
```

### Remote Paths
Remote paths are used to tell the Mach-O binary where it can search for the libraries it depends on. These load commands are parsed via YARA-X and can be leveraged in YARA rules.

To iterate through the rpahs used in load commands in the Mach-O binary, one can leverage the `rpaths` array from the `macho` module:

```yara
import "macho"

rule rpath_iter {
  condition:
    for any rpath in rpaths: (
        rpath contains "lib/swift/macosx"
    )
}
```

To detect if a specific `rpath` is present in the load commands, one can use the `has_rpath()` function:

```yara
import "macho"

rule rpath_query {
  condition:
    macho.has_rpath("@loader_path/../Frameworks")
}
```

### Dylibs
Dylibs are shared libraries leveraged by the Mach-O binary.

To iterate through the dylibs loaded in the Mach-O binary, one can iterate through the dylib structures parsed by YARA-X:

```yara
import "macho"

rule library_dylib_location {
    condition:
        for any d in macho.dylibs: (
            d.name contains "/Library/"
        )
}
```

To detect if a certain dylib is loaded via a load command in the binary, the `has_dylib()` function is available for use.

```yara
import "macho"

rule libsystem_use {
    condition:
        macho.has_dylib("/usr/lib/libSystem.B.dylib")
}
```

### Entitlements
Mach-O binaries can feature entitlements, which are XML properties for requesting certain permissions from the user/device that it is being executed on. These are parsed out into strings which are able to be queried via the `macho` module.

These entitlements can be leveraged in multiple ways.

One can iterate over the entitlements like so:

```yara
import "macho"

rule entitlements_example {
    condition:
        for any e in macho.entitlements: (
            e contains "com.apple.security"
        )
}
```

To detect a specific entitlement, one can also use the `has_entitlement()` function.

```yara
import "macho"

rule entitlements_example {
    condition:
        macho.has_entitlement("com.apple.security.device.microphone")
}
```

## Binary Similarity

If you wish to detect if a Mach-O binary is using a certain set of dylibs, imports, exports, entitlements, or more, you can leverage the respective `_hash()` function for each structure.

The hash algorithm is an MD5 hash of the deduplicated, sorted, and lowercased entries joined via a comma (`md5("dylib_1,dylib_2,dylib_n")`) found in the binary for each category.

### Dylib Hashing

```yara
import "macho"

rule dylib_hash_example {
    condition:
        macho.dylib_hash() == "c92070ad210458d5b3e8f048b1578e6d"
}
```

### Import Hashing

```yara
import "macho"

rule import_hash_example {
    condition:
        macho.import_hash() == "35ea3b116d319851d93e26f7392e876e"
}
```

### Export Hashing

```yara
import "macho"

rule export_hash_example {
    condition:
        macho.export_hash() == "6bfc6e935c71039e6e6abf097830dceb"
}
```

### Entitlement Hashing

```yara
import "macho"

rule entitlement_hash_example {
  condition:
    macho.entitlement_hash() == "cc9486efb0ce73ba411715273658da80"
}
```

# Conclusion
There are many features and structures parsed with the `macho` module in YARA-X, and only a subset of them were covered in this blog post. To fully explore what is possible with the `macho` module, please consult the [`macho module documentation`](https://virustotal.github.io/yara-x/docs/modules/macho/).