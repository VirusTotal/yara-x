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

YARA-X uses a configuration file to control the behavior of its various
commands. Currently, it supports settings for the `fmt` command, but additional
command options will be introduced in future updates.

By default, YARA-X looks for the configuration file at `${HOME}/.yara-x.toml`
when it starts. If the file is not present, default settings are used instead.

An example `.yara-x.toml` file is shown below, with comments that explain each
option.

```toml
# Config file for YARA-X.
#
# The `[fmt]` section controls the behavior of the "fmt" command, which is 
# responsible for formatting YARA rules. Settings are defined as key-value 
# pairs, using dot notation to specify different aspects of formatting.
# 
# The available namespaces are:
# - `rule`: Options that apply to formatting the overall rule structure.
# - `meta`: Options specific to the "meta" section of a rule.
# - `patterns`: Options specific to formatting the "patterns" section of a rule.

[fmt]

# Indent section headers. When enabled, section headers (like "condition:") will
# be indented to improve readability.
# 
# == Example ==
# 
# Before:
# rule a {
# condition:
# true
# }
#
# After:
# rule a {
#   condition:
#   true
# }
rule.indent_section_headers = true

# Indent the contents within each section. This controls whether the content 
# under each section header (e.g., "condition:") is indented.
# 
# == Example == 
#
# Before:
# rule a {
# condition:
# true
# }
#
# After:
# rule a {
#   condition:
#     true
# }
rule.indent_section_contents = true

# Number of spaces used for indentation.
# - Set to a positive integer to indicate the number of spaces per indentation 
#   level.
# - If set to `0`, tabs will be used instead of spaces.
# - To completely disable indentation, set both `rule.indent_section_headers` 
#   and `rule.indent_section_contents` to `false`.
rule.indent_spaces = 2

# Align metadata key-value pairs. This controls whether metadata values in the 
# "meta" section should be aligned for readability. When enabled, the key-value 
# pairs in metadata will be visually aligned to make them easier to compare.
# 
# == Example ==
#
# Before:
# rule a {
#   meta:
#     key = "a"
#     long_key = "b"
# }
#
# After (with alignment enabled):
# rule a {
#   meta:
#     key      = "a"
#     long_key = "b"
# }
#
# Note: Alignment is performed using spaces, regardless of the `rule.indent_spaces`
# setting.
meta.align_values = false

# Align pattern key-value pairs. Similar to `meta.align_values`, but applies to 
# the "patterns" section.
patterns.align_values = false
```