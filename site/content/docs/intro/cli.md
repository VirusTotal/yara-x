---
title: "Using the CLI"
description: "How to use YARA-X's command-line interface"
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "cli"
weight: 130
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

YARA-X provides a modern command-line interface (CLI) for performing common
tasks, like scanning files with YARA rules, compiling rules, etc. This tool
is named `yr` and is always followed by a top-level command, such as `scan`,
`compile`, `help` and so on.

Let's see the output of `yr help`:

```
> yr help
Usage:
    yr [COMMAND]

Commands:
  scan        Scan a file or directory
  compile     Compile rules to binary form
  dump        Show the data produced by YARA modules for a file
  completion  Output shell completion code for the specified shell
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

You can get more help for a specific command by using `yr help [COMMAND]` or
`yr [COMMAND] --help` (e.g: `yr help scan`, `yr scan --help`)

------

## scan

This is probably the most used command in the CLI, it allows to scan a file
or directory with one or more YARA rules. The syntax for this command is:

```
yr scan [OPTIONS] <RULES_PATH>... <TARGET_PATH>
```

The command receives one or more `<RULES_PATH>` arguments. Each `<RULES_PATH>`
is the path of YARA source file or a directory containing source files. When
`<RULES_PATH>` is a directory YARA-X iterates the directory recursively looking
for any `*.yar` or `*.yara` files.

`<TARGET_PATH>` is the path of the file or directory to be scanned.

The options supported by this command are:

### --compiled-rules, -C

Indicates that `<RULES_PATH>` is a file containing compiled rules, not YARA
source code. When this flag is used you must provide a single `<RULES_PATH>`.
YARA-X can't accept multiple files that contain compiled rules, however you
can compile multiple YARA source files into a single compiled file.

YARA rules are compiled using the [compile](#compile) command.

### --define, -d <VAR=VALUE>

Defines external variables.

Examples:

```
--define some_int=1
--define some_float=3.14
--define some_bool=true
--define some_str=\"foobar\"
```

### --disable-console-logs

Disables the output produced by the [console]({{< ref "console.md" >}}) module.

### --disable-warnings, -w

Disables all warnings when used alone, or disable specific warnings when
followed by comma-separated list of warnings identifiers.

Disable all warnings:

```
--disable-warnings
```

Disable warning `slow_patterns`:

```
--disable-warnings=slow_patterns
```

Disable warnings `slow_patterns` and `redundant_modifier`:

```
--disable-warnings=slow_patterns,redundant_modifier
```

Equivalent to the previous one, but using `--disable-warnings` multiple times:

```
--disable-warnings=slow_patterns --disable-warnings=redundant_modifier
```

### --negate, -n

Prints the rules that doesn't match instead of those that match.

### --output-format, -o <FORMAT>

Specify the output format. Available options are `text` and `ndjson`. By
default, the output format is `text`. The `ndjson` format, which stands for
newline-delimited JSON, presents the results as one JSON object per line. Each
JSON object details the matches for a single file. Here is an example output:

```text
{"path": "onefile.exe","rules": [{"identifier": "some_rule"}]}
{"path": "anotherfile.exe","rules":[{"identifier": "another_urle"}]}
```

Other options like `--print-strings` and `--print-namespace` also affect the
fields included in the JSON object. For example, using the `--print-namespace`
option adds a "namespace" field to each JSON object.

To parse the `ndjson` format, you can use the [jq](https://jqlang.github.io/jq/)
tool. For instance, to extract only the paths of the matching files, you can
run:

```shell
yr scan --output-format ndjson rules/test.yara /bin | jq .path
```

### --path-as-namespace

Use the path of each YARA source file as its namespace.

This is useful when you have multiple source files but some of them contain
rules with the same names. If you put the rules from all the files under the
same namespace, YARA is going to complain about the duplicated rule identifiers.
However, if every file is put under its own namespace the rule names won't
collide.

### --print-meta, -m

Prints the metadata associated to matching rules.

### --print-namespace, -e

Prints the namespace of matching rules.

### --print-strings, -s

Prints the matching patterns or strings.

### --print-tags, -g

Print the tags associated to matching rules.

### --relaxed-re-syntax

Use a more relaxed syntax check while parsing regular expressions.

YARA-X enforces stricter regular expression syntax compared to YARA. For
instance, YARA accepts invalid escape sequences and treats them as literal
characters (e.g., `\R` is interpreted as a literal `R`). It also allows some
special characters to appear unescaped, inferring their meaning from the
context (e.g., `{` and `}` in `/foo{}bar/` are literal, but in `/foo{0,1}bar/`
they form the repetition operator `{0,1}`).

This setting controls whether the compiler should mimic YARA's behavior,
allowing constructs that YARA-X doesn't accept by default.

### --scan-list

Indicate that `<TARGET_PATH>` is a file containing the paths to be scanned.

`<TARGET_PATH>` must be a text file containing one path per line. The paths
must be either absolute paths, or relative to the current directory.

### --skip-larger <FILE_SIZE>

Skips files larger than the given size in bytes.

### --tag <TAG>, -t <TAG>

Print only the matching rules that have the given tag.

### --threads, -p <NUM_THREADS>

Use the specified number of threads. By default, it uses as many threads as
CPU cores.

### --timeout, -a <SECONDS>

Abort scanning after the given number of seconds.


------

## compile

This command allows compiling one or more YARA source files into a single binary
file. The binary file can be passed later to the [scan](#scan) command by using
the `--compiled-rules` option. This way you can compile the rules once, and
re-used for multiple scan operations.

The syntax for this command is:

```
yr compile [OPTIONS] <RULES_PATH>...
```

Each `<RULES_PATH>` is the path of YARA source file or a directory containing
source files. When`<RULES_PATH>` is a directory YARA-X iterates the directory
recursively looking for any `*.yar` or `*.yara` files.

### --disable-warnings

See [--disable-warnings](#--disable-warnings) for the scan command.

### --output, -o <OUTPUT_PATH>

Specify the path for the output binary file containing the compiled rules. By
default, is `output.yarc`.

### --path-as-namespace

See [--path-as-namespace](#--path-as-namespace) for the scan command.

### --relaxed-re-syntax

See [--relaxed-re-syntax](#--relaxed-re-syntax) for the scan command.

------

## dump

This command allows inspecting the output produced by YARA-X modules for a
file. The syntax for this command is:

```
yr dump [OPTIONS] [FILE]
```

This command will pass the file to multiple YARA-X modules, including [pe]({{<
ref "pe.md" >}}),
[macho]({{< ref "macho.md" >}}), [elf]({{< ref "elf.md" >}}), [dotnet]({{<
ref "dotnet.md" >}}), and [lnk]({{< ref "lnk.md" >}}). The structure produced
by all these modules will dumped to stdout in YAML format.

If the file is not provided it will be read from stdin.

### --output-format, -o <FORMAT>

Specify the output format. Possible values are: `json` and `yaml`. The default
value is `yaml`.

### --module, -m <module>

Specify the modules that you are interested in. Possible values
are: `lnk`, `macho`, `elf`, `pe` and `dotnet`. By default all modules are tried,
but only the modules that produced some information will appear in the output.

This option can be used multiple times for specifying more than one module.
For example:

```
yr dump --module=pe --module=dotnet [FILE]
```

### --no-colors

Turn off output colors.

By default, both YAML and JSON outputs contains colors that improves their
legibility, this option turns off colors. When the output of this command is
redirected from stdout to a file, colors are turned off automatically, even
if `--no-colors` is missing.