YARA-X Config Guide
===================

YARA-X uses a configuration file for controlling the behavior of different
commands. It currently supports the `fmt` command, but others will be added in
the future.

The `yr` command looks in `${HOME}/.yara-x.toml` when starting up. If that file
does not exist the default values are used.

An example `.yara-x.toml` file is below, with comments that explain each option.
This is the definitive list of supported configuration options, and will be
updated as more are added.

```toml
# Config file for YARA-X.

# Any options that are not valid are ignored. However, valid keys with an
# invalid type will cause a parsing error. For example, if you set
# rule.indent_spaces to false, it will result in a parsing error.
pants = false # Invalid keys are ignored.

# The configuration of the "fmt" subcommand can be controlled by options in the
# "fmt" section. Each line is a key-value pair where the key uses a dot notation
# to deliniate different options. The "rule" namespace are for options that
# apply to the rule as a whole, while the "meta" and "patterns" namespaces are
# for options that only apply to those sections in a rule.
[fmt]
# Indent section headers so that:
#
# rule a {
# condition:
# true
# }
#
# Becomes:
#
# rule a {
#   condition:
#   true
# }
rule.indent_section_headers = true

# Indent section contents so that:
# rule a {
# condition:
# true
# }
#
# Becomes:
#
# rule a {
#   condition:
#     true
# }
rule.indent_section_contents = true

# Number of spaces to use for indentation. Setting this to 0 will use one tab
# character per level of indentation. To disable indentation entirely use
# rule.indent_section_headers and rule.indent_section_contents
rule.indent_spaces = 2

# Align metadata values so that:
#
# rule a {
#   meta:
#     key = "a"
#     long_key = "b"
# }
#
# Becomes:
#
# rule a {
#   meta:
#     key      = "a"
#     long_key = "b"
# }
#
# Note that alignment is done with spaces, regardless of rule.indent_spaces
# setting.
meta.align_values = false

# Same as meta.align_values but applies to patterns.
patterns.align_values = false
```