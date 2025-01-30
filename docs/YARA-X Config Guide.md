YARA-X Config Guide
===================

YARA-X uses a configuration file for controlling the behavior of different
commands. It currently supports the `fmt` and `check` commands. More may be
added in the future.

The `yr` command looks in `${HOME}/.yara-x.toml` when starting up. If that file
does not exist the default values are used.

An example `.yara-x.toml` file is below, with comments that explain each option.
The values for each option are the default values that are used if the option
is omitted.

This is the definitive list of supported configuration options, and will be
updated as more are added.

```toml
# Config file for YARA-X.

# Any options that are omitted from your config file will use the default value.

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

# Add a newline before the curly brace that starts the rule body.
#
# rule a {
#   condition:
#     true
# }
#
# Becomes:
#
# rule a
# {
#   condition:
#     true
# }
#
# Note: If you have multiple newlines before the curly brace and this is set to
# `true` then this will ensure exactly two newlines are left.
rule.newline_before_curly_brace = false

# Add an empty line before section headers so that:
#
# rule a {
#   meta:
#     date = "20240705"
#   strings:
#     $ = "AXSERS"
# }
#
# Becomes:
#
# rule a {
#   meta:
#     date = "20240705"
#
#   strings:
#     $ = "AXSERS"
# }
#
# Note: This does not apply to the first section header defined. All empty lines
# before the first section header are always removed.
rule.empty_line_before_section_header = true

# Add an empty line after section headers so that:
#
# rule a {
#   strings:
#     $ = "AXSERS"
# }
#
# Becomes:
#
# rule a {
#   strings:
#
#     $ = "AXSERS"
# }
rule.empty_line_after_section_header = false

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
meta.align_values = true

# Same as meta.align_values but applies to patterns.
patterns.align_values = true

# The "check" section controls the behavior of the "check" command, which is
# used to enforce standards on various aspects of the rule like metadata and
# rule name.
[check]
# Table (dictionary) of required metadata identifiers and their requirements.
#
# The key is the identifier and the value is a table that describes the
# requirements for that identifier - what type it must have and if it is
# required or not.
#
# Supported types are "string", "integer", "float", "bool", "md5",
# "sha1", "sha256", or "hash".
#
# To require that there be an "author" metadata field and the value must be a
# string use this:
#
# metadata = { author = { type = "string", required = true } }
#
# To specify that the "date" metadata field be an integer if it exists, but it
# isn't required to exist, use this:
#
# metadata = { date = { type = "integer" } }
#
# The default for "required" is false.
#
# The "md5", "sha1" and "sha256" types are convenience types that check for a
# string that is the correct length and only contains valid hexadecimal digits.
#
# The "hash" type is another convenience type that checks for any of the valid
# hashes mentioned above. It is meant to be more flexible than requiring a
# specific hash type in every rule.
#
# For example, to require that every rule have a metadata field named "sample"
# and that the type of that field be an md5, sha1 or sha256 string use this:
#
# metadata = { sample = { type = "hash", required = true } }
#
# NOTE: Inline tables must be expressed as a single line and no trailing comma
# is allowed.
#
# The default value is an empty table.
metadata = {}

# A regular expression which must match rule names. For example, if you require
# that every rule start with a "category" description followed by an underscore
# you could use something like this:
#
# rule_name_regexp = "^(APT|CRIME)_"
#
# The default is no regular expression.
rule_name_regexp = ""
```