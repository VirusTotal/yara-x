pub const CHECK_LONG_HELP: &str = r#"Check if YARA source files are correct

If <RULES_PATH> is a directory, all files with extensions `.yar` and `.yara` will be checked.
This behavior can be changed by using the `--filter` option."#;

pub const COMPILED_RULES_LONG_HELP: &str = r#"Indicate that <RULES_PATH> is a file containing compiled rules

YARA rules can be compiled with the `yr compile` command. The file produced by
this command can be passed later to `yr scan` by using this flag."#;

pub const COMPLETION_LONG_HELP: &str = r#"Output shell completion code for the specified shell

Examples:

yr completion bash > $(brew --prefix)/etc/bash_completion.d/yr
yr completion zsh > "${fpath[1]}/_yr""#;

pub const CONFIG_FILE: &str = r#"Config file for YARA-X

Specifies a config file which controls the behavior of YARA-X. If config file is not
specified, ${HOME}/.yara-x.toml is used. If it does not exist the default options are
applied.

See https://virustotal.github.io/yara-x/docs/cli/config-file/ for supported options."#;

pub const DEFINE_LONG_HELP: &str = r#"Define external variable

Examples:

--define some_int=1
--define some_float=3.14
--define some_bool=true
--define some_str=\"foobar\""#;

pub const DUMP_LONG_HELP: &str = r#"Show the data produced by YARA modules for a file

YARA modules analyze files and extract information from them. This command shows all
the data produced by one or more YARA module for the given file. If no module is
explicitly specified with the `--module` option, any module for which YARA produced
some information will be shown.

If the file is not provided it will be read from stdin.

Examples:

yr dump --module pe SOMEFILE
yr dump --module pe --module dotnet SOMEFILE
cat SOMEFILE | yr dump"#;

pub const DISABLE_WARNINGS_LONG_HELP: &str = r#"Disable warnings

When used alone all warnings are disabled. It can receive a comma-separated
list of with the names of the warnings to disable.

Examples:

--disable-warnings
--disable-warnings=slow_pattern
--disable-warnings=slow_rules,redundant_modifier"
--disable-warnings=slow_rules --disable-warnings=redundant_modifier"#;

pub const FILTER_LONG_HELP: &str = r#"Only check files that match the given pattern

Patterns can contains the following wildcards:

?      matches any single character.

*      matches any sequence of characters, except the path separator.

**     matches any sequence of characters, including the path separator.

[...]  matches any character inside the brackets. Can also specify ranges of
       characters (e.g. [0-9], [a-z])

[!...] is the negation of [...]

This option can be used more than once with different patterns. In such cases
files matching any of the patterns will be checked.

When no filter is specified, the following ones are used by default:

--filter='**/*.yara' --filter='**/*.yar'"#;

pub const FMT_CHECK_MODE: &str = r#"Run in 'check' mode

Doesn't modify the files. If formatting is required prints the names of files
that would be modified and exits with 1. Exits with 0 if all files were already
formatted correctly."#;

pub const FMT_TAB_SIZE: &str = r#"Tab size (in spaces) used in source files

If the input contains tab characters, the formatter uses this value to determine how
many spaces each tab represents. Setting this incorrectly can lead to misaligned 
formatting when the code mixes tabs and spaces."#;

pub const FIX_ENCODING_LONG_HELP: &str = r#"Convert source files to UTF-8

YARA-X is stricter that YARA with respect to invalid UTF-8 characters in source
code. This command allows to convert your YARA source files to UTF-8 encoding if
they are not.

If <RULES_PATH> is a directory, all files with extensions `.yar` and `.yara` will
be converted. This behavior can be changed by using the `--filter` option."#;

pub const FIX_WARNINGS_LONG_HELP: &str = r#"Automatically fix warnings

This command automatically resolves fixable YARA-X warnings. It accepts the same
options as the compile command; however, instead of outputting a compiled rules file,
it directly modifies the source files to fix the warnings."#;

pub const INCLUDE_DIR_LONG_HELP: &str = r#"Directory in which to search for included files

If not given, the current working directory is used. May be specified multiple 
times; directories will be searched in order."#;

pub const IGNORE_MODULE_LONG_HELP: &str = r#"Ignore rules that use the specified module

Rules that use the specified module will be ignored, as well as any rules that
depends directly or indirectly on such rules.

This option can be used more than once for ignored different modules."#;

pub const NO_MMAP_LONG_HELP: &str = r#"Don't use memory-mapped files

By default, large files are memory-mapped as this is typically faster than 
copying file contents into memory. However, this approach has a drawback: if 
another process truncates the file during scanning, a `SIGBUS` signal may 
occur and the YARA-X process will crash.
   
This option disables memory mapping and forces the scanner to always read files
into an in-memory buffer instead."#;

pub const MAX_MATCHES_PER_PATTERN_LONG_HELP: &str = r#"Maximum number of matches per pattern

When some pattern reaches the maximum number of occurrences it won't produce
more matches. This can affect rules that rely on the number of occurrences of
some pattern. For instance, the expression `#a > 100` will be false if this 
limit is set to 100 or less."#;

pub const MODULE_DATA_LONG_HELP: &str = r#"Pass FILE's content as extra data to MODULE

Some modules require supplementary data to work, in addition to the scanned
file. This option allows you to provide that extra data. The flag can be used
multiple times to supply data to different modules. The content of the FILE is
loaded and interpreted by the respective module.

Examples:

--module-data=mymodule0=./example0.json --module-data=mymodule1=./example1.json

In this example, the contents of example0.json and example1.json will be passed
to mymodule0 and mymodule1, respectively."#;

pub const OUTPUT_FORMAT_LONG_HELP: &str = r#"Output format

The format in which results will be displayed. Any errors or warnings will not
be in this format, only results.

Examples:

--output-format=ndjson"#;

pub const RECURSIVE_LONG_HELP: &str = r#"Walk directories recursively

When <RULES_PATH> is a directory, this option enables recursive directory traversal.
You can optionally specify a <MAX_DEPTH> to limit how deep the traversal goes:

--recursive     process nested subdirectories with no limits.
--recursive=0   process only the files in <TARGET_PATH> (no subdirectories)
--recursive=3   process up to 3 levels deep, including nested subdirectories

If --recursive is not specified, the default behavior is equivalent to --recursive=0.

Examples:

--recursive
--recursive=3"#;

pub const THREADS_LONG_HELP: &str = r#"Use the specified number of threads

The default value is automatically determined based on the number of CPU cores."#;

pub const SCAN_LIST_LONG_HELP: &str = r#"Indicate that TARGET_PATH is a file containing the paths to be scanned

<TARGET_PATH> must be a text file containing one path per line. The paths must
be either absolute paths, or relative to the current directory."#;

pub const SCAN_LONG_HELP: &str = r#"Scan a file or directory

<RULES_PATH> can be the path to a file containing YARA rules, or the path to a directory
containing *.yar or *.yara files. When <RULES_PATH> is a directory, it will be traversed
recursively. Multiple <RULES_PATH> can be specified.

Each path can be prefixed with a namespace, the namespace and the path are separated by
a semicolon (`:`), like in `namespace:rules_file.yar`. All rules in the path will be put
under the specified namespace, isolated from rules in other namespaces.

<TARGET_PATH> is the file or directory that will be scanned.

Examples:

yr scan rules_file.yar scanned_file
yr scan rules_dir scanned_file
yr scan namespace:rules_file.yar scanned_file
yr scan namespace:rules_dir scanned_file"#;

pub const SCAN_PRINT_STRING_LONG_HELP: &str = r#"Print matching patterns

The printed patterns can be optionally limited to <N> characters. By default 
they are limited to 120 characters.

Examples:

--print-strings
--print-strings=50"#;

pub const SCAN_RECURSIVE_LONG_HELP: &str = r#"Scan directories recursively

When <TARGET_PATH> is a directory, this option enables recursive scanning
of its contents. You can optionally specify a <MAX_DEPTH> to limit how deep
the scan goes:

--recursive     scan nested subdirectories with no depth limit.
--recursive=0   scan only the files in <TARGET_PATH> (no subdirectories)
--recursive=3   scan up to 3 levels deep, including nested subdirectories

If --recursive is not specified, the default behavior is --recursive=0.

Examples:

--recursive
--recursive=3"#;
