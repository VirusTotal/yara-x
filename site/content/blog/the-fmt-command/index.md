---
title: "The fmt command"
description: ""
summary: ""
date: 2024-10-03T00:00:00+01:00
lastmod: 2024-10-03T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Victor M. Alvarez" ]
pinned: false
homepage: false
seo:
  title: "The fmt command" # custom title (optional)
  description: "An introduction to the YARA-X automatic rule formatter" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Consistent code formatting isn't just about aesthetics; it makes code easier to
read, understand, and maintain. For many programming languages, there are tools
that help you enforce a consistent coding style across your codebase. Even
though YARA is not a traditional programming language, maintaining a consistent
style across all your YARA rules is also important, especially when
collaborating with a team or working on a large set of signatures. However,
until now, the YARA community lacked a way to guarantee a homogeneous style for
YARA rules.

The `fmt` command—a powerful tool that helps standardize the look of your YARA
rules—was introduced in YARA-X 0.8.0, but in version 0.9.0 it became
customizable. This post will show you how to use this command, explore the
options available, and guide you in creating your own configuration file for the
best possible formatting experience.

## Getting started with the configuration file

The `fmt` command in YARA-X draws its formatting rules from a configuration file
named `.yara-x.toml`. By default, YARA-X looks for this file in your home
directory (`${HOME}/.yara-x.toml`). If the file doesn’t exist, YARA-X will use
its built-in default settings. Let’s explore what you can do with a customized
`.yara-x.toml` file.

Here is an example configuration file:

```toml
# YARA-X Configuration File (.yara-x.toml)

[fmt]

# Indent section headers
rule.indent_section_headers = true

# Indent the contents within each section
rule.indent_section_contents = true

# Number of spaces used for indentation
rule.indent_spaces = 2

# Align metadata key-value pairs
meta.align_values = false

# Align pattern key-value pairs
patterns.align_values = false
```

Let’s break down these settings, see what they do, and understand how they can
help standardize your YARA rule formatting.

### Indenting section headers and contents

The `[fmt]` section in your `.yara-x.toml` file provides several settings to
control indentation:

`rule.indent_section_headers` determines whether section headers (
like `meta:`, `strings:`, and `condition:`) should be indented within a YARA
rule. If set to `true`, the headers will be indented with respect to the rule's
body.

Example (with indentation enabled):

```yara
rule example_rule {
  meta:
    description = "An example rule"

  strings:
    $a = "test"

  condition:
    $a
}
```

Example (with indentation disabled):

```yara
rule example_rule {
meta:
  description = "An example rule"

strings:
  $a = "test"

condition:
  $a
}
```

`rule.indent_section_contents` controls whether the contents within each section
are further indented. For example, inside the `condition:` section, any
conditions
are indented relative to the section header. This setting can help make your
rules more readable by visually distinguishing between headers and their
corresponding content.

Example (with indentation enabled):

```yara
rule example_rule {
  meta:
    description = "An example rule"

  strings:
    $a = "test"

  condition:
    $a
}
```

Example (with indentation disabled):

```yara
rule example_rule {
  meta:
  description = "An example rule"

  strings:
  $a = "test"

  condition:
  $a
}
```

### Choosing the number of spaces for indentation

`rule.indent_spaces` specifies how many spaces are used for indentation. You
can set it to any positive integer (common choices are 2 or 4 spaces). If you
prefer to use tabs instead of spaces, simply set `rule.indent_spaces` to 0.

### Aligning metadata and patterns

`meta.align_values` controls whether the key-value pairs in the `meta:` section
should be aligned. When set to `true`, the `=` signs for all metadata entries
will be aligned, making it easier to read and compare information.

Example (with alignment enabled):

```yara
rule example_rule {
  meta:
    author      = "Jane Doe"
    description = "Detects example strings"
}
```

Example (with alignment disabled):

```yara
rule example_rule {
  meta:
    author = "Jane Doe"
    description = "Detects example strings"
}
```

`patterns.align_values` is similar to `meta.align_values`, but his controls the
alignment of key-value pairs in the `strings:` section of the rule.

Example (with alignment enabled):

```yara
rule example_rule {
  strings:
    $short     = "abc"
    $longer    = { 01 02 03 }
    $very_long = /regex/
}
```

Example (with alignment disabled):

```yara
rule example_rule {
  strings:
    $short = "abc"
    $longer = { 01 02 03 }
    $very_long = /regex/
}
```

## Conclusion

YARA-X’s `fmt` command, especially in its customizable form, is a game-changer
for anyone working with YARA rules. It allows you to bring structure,
readability, and consistency to your rules, making them easier to maintain and
less error-prone.

If you haven't yet tried out YARA-X’s `fmt` command, now is the perfect time to
start. Consistency, after all, is key to effective collaboration and efficient
threat hunting.