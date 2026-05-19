---
title: "Config file"
description: "The format of the config file for YARA-X"
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "cli-config"
weight: 130
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

YARA-X uses a configuration file for controlling the behavior of different
commands. The file is written in [TOML](https://toml.io/) format, and it
currently
supports the `fmt` and `check` commands. More may be added in the future.

The `yr` command looks in `${HOME}/.yara-x.toml` when starting up. If that file
does not exist the default values are used.

This is the definitive list of supported configuration options, invalid keys
or incorrect types will result in a parsing error while loading the
configuration
file.

## The [fmt] section

The `[fmt]` section controls the behavior of the `fmt` command, which formats
YARA-X rules for readability and consistency.

```toml
[fmt]
rule.indent_section_headers = true
rule.indent_section_contents = true
rule.indent_spaces = 2
rule.newline_before_curly_brace = false
rule.empty_line_before_section_header = true
rule.empty_line_after_section_header = false
meta.align_values = true
patterns.align_values = true
```

These options control the formatting of rules:

- `rule.indent_spaces`: Sets the number of spaces per indentation level. Set
  to `0` to use tab characters.


- `rule.indent_section_headers`: Indents section headers within a rule body.

  ```
  // rule.indent_section_headers = false
  rule a {
  condition:
  true
  }
  ```

  ```
  // rule.indent_section_headers = true (default)
  rule a {
    condition:
    true
  }
  ```

- `rule.indent_section_contents`: Indents the content within each section.

  ```
  // rule.indent_section_contents = false
  rule a {
    condition:
    true
  }
  ```

  ```
  // rule.indent_section_contents = true (default)
  rule a { 
    condition:
      true
  }

- `rule.newline_before_curly_brace`: Ensures a newline appears before the
  opening `{` of the rule body when set to `true`.

  ```
  // rule.newline_before_curly_brace = false (default)
  rule a {
    condition:
    true
  }
  ```

  ```
  // rule.newline_before_curly_brace = true
  rule a 
  {
    condition:
      true
  }  
  ```

- `rule.empty_line_before_section_header`: Adds an empty line before each
  section header, except the first one.

  ```
  // rule.empty_line_before_section_header = false (default)
  rule a {
    meta:
      date = "20240705"
    strings:
      $ = "AXSERS"
  }
  ```

  ```
  // rule.empty_line_before_section_header = true
  rule a {
    meta:
      date = "20240705"
  
    strings:
      $ = "AXSERS"
  }
  ```

- `rule.empty_line_after_section_header`: Adds an empty line after each section
  header.

  ```
  // rule.empty_line_after_section_header = false (default)
  rule a {
    strings:
      $ = "AXSERS"
  }
  ```

  ```
  // rule.empty_line_after_section_header = true
  rule a {
    strings:
  
      $ = "AXSERS"
  }
  ```

- `meta.align_values`: Aligns metadata values for better readability.

   ```
   // meta.align_values = false (default)
   rule a {
     meta:
       key = "a"
       long_key = "b"
   }         
   ```

   ```
   // meta.align_values = true
   rule a {
     meta:
       key      = "a"
       long_key = "b"
   }   
   ```

- `patterns.align_values`: Aligns pattern values in a similar manner.

   ```
   // patterns.align_values = false (default)
   rule a {
     strings:
       $s = "a"
       $long = "b"
   }         
   ```

   ```
   // patterns.align_values = true
   rule a {
     strings:
       $s    = "a"
       $long = "b"
   }   
   ```

---

## The [check] section

The `[check]` section controls the behavior of the `check` command, which
enforces standards on rule naming and metadata fields.

### Rule name validation

```toml
[check.rule_name]
regexp = "^(APT|CRIME)_"
error = false
```

These options define constraints for rule names:

- `regexp`: Specifies a regular expression pattern that rule names must match.
- `error`: Determines whether a rule name violation is treated as an
  error (`true`) or just a warning (`false`).

### Metadata validation

Each entry in `check.metadata` is a table specifying the requirements for a
metadata field.

```toml
[check.metadata]
author = { type = "string", required = true }
date = { type = "integer" }
file = { type = "hash", required = true, error = true }
severity = { type = "string", regexp = "(LOW|HIGH)" }
```

{{< callout title="Warning">}}

Inline tables must be expressed as a single line and no trailing comma is
allowed.

{{< /callout >}}

- The `author` field must be a string and is required.
- The `date` field must be an integer but is optional.
- The `file` field must contain a valid hash (`md5`, `sha1`, or `sha256`)
  and is required. If the field is not present or has the wrong type it will
  cause
  an error instead of a warning.
- The `severity` field must be a string that matches the regexp `(LOW|HIGH)`.

Supported metadata types are `"string"`, `"integer"`, `"float"`, `"bool"`,
`"md5"`, `"sha1"`, `"sha256"`, or `"hash"`. The `"md5"`, `"sha1"` and `"sha256"`
types are convenience types that check for a string that is the correct length
and only contains valid hexadecimal digits.

The `"hash"` type is another convenience type that checks for any of the valid
hashes mentioned above. It is meant to be more flexible than requiring a
specific hash type in every rule.

Metadata entries of type `"string"` can be accompanied by a `regexp` field that
contains a regular expression that must be matched by the metadata value. This
field is ignored if the type is other than `"string"`.

The default values for `required` and `error` are both `false`. This means that
metadata fields are optional by default, and if they don't comply with the
requirements established in the configuration file YARA-X will raise a warning.
By setting `error` to `true` these warnings are turned into errors.

### Tag validation

```toml
[check.tags]
allowed = ["APT", "CRIME"]
regexp = "^(APT|CRIME)_"
error = false
```

These options define constraints for rule tags:

- `allowed`: Specifies a list of allowed tags.
- `regexp`: Specifies a regular expression pattern that rule tags must match.
- `error`: Determines whether a tag violation is treated as an error (`true`) or
  just a warning (`false`).

If both `allowed` and `regexp` are specified the check command will use the
`allowed` option as it is more explicit.

The default value for `error` is `false`. This means that if tags do not comply
with the requirements established in the configuration file YARA-X will raise a
warning. By setting `error` to `true` these warnings are turned into errors.

---

## The [warnings] section

{{< callout >}} 
New in version 1.2.0 
{{< /callout >}}

The `[warnings]` section allows you to configure which warnings are shown when
compiling your rules. 

While you can disable specific warnings using the [`--disable-warnings`]({{< ref "commands.md" >}}#--disable-warnings) 
command-line option, doing so for every invocation of the CLI becomes tedious.

To simplify this, you can permanently disable specific warnings in your 
configuration file:


```toml
[warnings]
text_as_hex = { disabled = true }
```

In the example above, the `text_as_hex` warning is disabled globally for all
CLI invocations. You can disable multiple warnings by listing them in the
same section:

```toml
[warnings]
text_as_hex = { disabled = true }
unsatisfiable_expr = { disabled = true }
```

---

## Example file

```toml
[fmt]
rule.indent_spaces = 2
rule.indent_section_headers = true
rule.indent_section_contents = true

rule.newline_before_curly_brace = false
rule.empty_line_before_section_header = true
rule.empty_line_after_section_header = false

meta.align_values = true
patterns.align_values = true

[check.rule_name]
regexp = "^(APT|CRIME)_"
error = false

[check.metadata]
file = { type = "hash", required = true, error = true }
author = { type = "string", required = true }
date = { type = "integer" }

[check.tags]
allowed = ["APT", "CRIME"]
error = true

[warnings]
text_as_hex = { disabled = true }
unsatisfiable_expr = { disabled = true }
```
```