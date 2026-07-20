---
title: "External global variables"
description: "How to use external variables in YARA-X"
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "external_variables"
weight: 270
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Rules can reference external variables that are defined at compile time.
For instance, consider the following rule:

```yara
rule VariableExample1 {
    condition:
        ext_var == 10
}
```

Here, `ext_var` is an external variable that is defined when the rule is
compiled with the `--define ext_var=VALUE` flag. 

External variables can be integers, floats, strings, or booleans. Integer variables can
replace integer constants in conditions, while boolean variables can act as
boolean expressions. For example:

```yara
rule VariableExample2 {
    condition:
        bool_ext_var or filesize < int_ext_var
}
```

The above rule may be compiled with the flags 
`-d bool_ext_var=true -d int_ext_var=100` for example.

External variables of type `string` can be used with any operators that works
on strings, like `contains`, `startswith`, `endswith`, etc. Let's see some
examples:

```yara
rule ContainsExample {
    condition:
        string_ext_var contains "text"
}

rule CaseInsensitiveContainsExample {
    condition:
        string_ext_var icontains "text"
}

rule StartsWithExample {
    condition:
        string_ext_var startswith "prefix"
}

rule EndsWithExample {
    condition:
        string_ext_var endswith "suffix"
}

rule MatchesExample {
    condition:
        string_ext_var matches /[a-z]+/
}
```

The rules above could be compiled with the flag `-d string_ext_var=\"Hello\"`
for example.

## Struct variables

External variables can also be structs. Struct fields are accessed using
dot notation. Keys must be valid YARA identifiers, and values can be booleans,
integers, floats, strings, nested structs, or arrays.

Struct variables can only be defined via the API, not through the `--define`
command-line flag. For example, in Python:

```python
compiler.define_global("file_info", {
    "name": "malware.exe",
    "size": 200000,
    "is_signed": False,
})
```

The struct fields can then be used in rule conditions:

```yara
rule StructExample {
    condition:
        file_info.name == "malware.exe" and
        file_info.size > 100000 and
        not file_info.is_signed
}
```

## Array variables

Structs can contain arrays. All elements in an array must be the same type
(homogeneous). Arrays of integers, floats, booleans, strings, and structs are
supported. Note that bare arrays cannot be top-level external variables — they
must be wrapped in a struct.

Arrays can be iterated using `for any ... in` or `for all ... in` expressions:

```python
compiler.define_global("data", {
    "items": [
        {"name": "indicator_1", "severity": 3},
        {"name": "indicator_2", "severity": 9},
    ]
})
```

The array items can then be used in rule conditions:

```yara
rule ArrayOfStructsExample {
    condition:
        for any item in data.items : (
            item.severity > 7
        )
}
```

## Defining external variables

Every external variable used in your rules must be defined at compile time.
For scalar types (integers, floats, strings, and booleans) this can be done using the
`--define VAR=VALUE` option (or `-d VAR=VALUE`) in the command-line tool.
Struct and array variables require the API.
(Like [this one](
https://docs.rs/yara-x/latest/yara_x/struct.Compiler.html#method.define_global)
in Rust or
[this one]({{< ref "python.md" >}}#define_globalidentifier-value)
in Python.)
