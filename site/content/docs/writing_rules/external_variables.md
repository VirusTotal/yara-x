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

External variables enable rules to depend on dynamic values from external
sources. For instance, consider the following rule:

```
rule VariableExample1 {
    condition:
        ext_var == 10
}
```

Here, `ext_var` is an external variable whose value is determined at
run-time. External variables can be integers, strings, or booleans, depending
on their assigned value.

Integer variables can replace integer constants in conditions, while boolean
variables can act as boolean expressions. For example:

```yara
rule VariableExample2 {
    condition:
        bool_ext_var or filesize < int_ext_var
}
```

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

rule CaseInsensitiveEqualsExample {
    condition:
        string_ext_var iequals "FoO"
}

rule MatchesExample {
    condition:
        string_ext_var matches /[a-z]+/
}
```

Every external variable used in your rules must be defined when the rules
are being compiled. This can be done using the `--define` option (or `-d`) in
the command-line tool, or by using the appropriate API.
(like [this one](
https://docs.rs/yara-x/latest/yara_x/struct.Compiler.html#method.define_global)
in Rust or
[this one]({{< ref "python.md" >}}#define_globalidentifier-value)
in Python).

