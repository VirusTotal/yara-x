pub const CHECK_LONG_HELP: &str = r#"Check if YARA source files are syntactically correct

If <PATH> is a directory, all files with extensions `yar` and `yara` will be
checked. The `--filter` option allows changing this behavior."#;

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

The absense of this options is equivalent to using this:

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
