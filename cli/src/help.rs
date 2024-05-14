pub const CHECK_LONG_HELP: &str = r#"Check if YARA source files are correct

If <RULES_PATH> is a directory, all files with extensions `.yar` and `.yara` will be checked. 
This behavior can be changed by using the `--filter` option."#;

pub const THREADS_LONG_HELP: &str = r#"Use the specified number of threads

The default value is automatically determined based on the number of CPU cores."#;

pub const DEPTH_LONG_HELP: &str = r#"Walk directories recursively up to a given depth

This is ignored if <RULES_PATH> is not a directory. When <MAX_DEPTH> is 0 it means
that files located in the specified directory will be processed, but subdirectories
won't be traversed. By default <MAX_DEPTH> is infinite."#;

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

pub const DEFINE_LONG_HELP: &str = r#"Define external variable

Examples:

--define some_int=1
--define some_float=3.14
--define some_bool=true
--define some_str=\"foobar\""#;

pub const COMPILED_RULES_HELP: &str = r#"Indicates that <RULES_PATH> is a file containing compiled rules

YARA rules can be compiled with the `yr compile` command. The file produced by
this command can be passed later to `yr scan` by using this flag."#;

pub const DUMP_LONG_HELP: &str = r#"Show the data produced by YARA modules for a file

YARA modules analyze files and extract information from them. This command shows all the 
data produced by one ore more YARA module for the given file. If no module is explictly 
specified with the `--module` option, any module for which YARA produces information will
be shown. 

Examples:

yr dump --module pe SOMEFILE
yr dump --module pe --module dotnet SOMEFILE
"#;

pub const COMPLETION_LONG_HELP: &str = r#"Output shell completion code for the specified shell

Examples:

yr completion bash > $(brew --prefix)/etc/bash_completion.d/yr
yr completion zsh > "${fpath[1]}/_yr"
"#;

pub const SCAN_LONG_HELP: &str = r#"Scan a file or directory

<RULES_PATH> can be the path to a file containing YARA rules, or the path to a directory
containing *.yar or *.yara files. When <RULES_PATH> is a directory, it will be traversed 
recursively. Multiple <RULES_PATH> can be specified.

<TARGET_PATH> is the file or directory that will be scanned.

Examples:

yr scan rules_file.yar scanned_file
yr scan rules_dir scanned_file
"#;
