import collections

from typing import Any, Dict, BinaryIO, TextIO, Optional, Tuple, final

class CompileError(Exception):
    r"""
    Error occurred while compiling rules.
    """

class ScanError(Exception):
    r"""
    Error occurred during a scan operation.
    """

class TimeoutError(Exception):
    r"""
    Error indicating that a timeout occurred during a scan operation.
    """

@final
class Compiler:
    r"""
    Compiles YARA source code producing a set of compiled [`Rules`].
    """
    def __new__(
        cls,
        relaxed_re_syntax: bool = False,
        error_on_slow_pattern: bool = False,
        includes_enabled: bool = True,
    ) -> Compiler:
        r"""
        Creates a new [`Compiler`].

        The `relaxed_re_syntax` argument controls whether the compiler should
        adopt a more relaxed syntax check for regular expressions, allowing
        constructs that YARA-X doesn't accept by default.

        YARA-X enforces stricter regular expression syntax compared to YARA.
        For instance, YARA accepts invalid escape sequences and treats them
        as literal characters (e.g., \R is interpreted as a literal 'R'). It
        also allows some special characters to appear unescaped, inferring
        their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
        literal, but in `/foo{0,1}bar/` they form the repetition operator
        `{0,1}`).

        The `error_on_slow_pattern` argument tells the compiler to treat slow
        patterns as errors, instead of warnings.

        The `includes_enabled` argument controls whether the compiler should
        enable or disable the inclusion of files with the `include` directive.
        """
        ...

    def add_source(self, src: str, origin: Optional[str] = None) -> None:
        r"""
        Adds a YARA source code to be compiled.

        This function may be invoked multiple times to add several sets of YARA
        rules before calling [`Compiler::build`]. If the rules provided in
        `src` contain errors that prevent compilation, the function will raise
        an exception with the first error encountered. Additionally, the
        compiler will store this error, along with any others discovered during
        compilation, which can be accessed using [`Compiler::errors`].

        Even if a previous invocation resulted in a compilation error, you can
        continue calling this function. In such cases, any rules that failed to
        compile will not be included in the final compiled set.

        The optional parameter `origin` allows to specify the origin of the
        source code. This usually receives the path of the file from where the
        code was read, but it can be any arbitrary string that conveys information
        about the source code's origin.
        """
        ...

    def add_include_dir(self, dir: str) -> None:
        r"""
        Adds a directory to the list of directories where the compiler should
        look for included files.
        """
        ...

    def enable_includes(self, yes: bool) -> None:
        r"""
        Enables or disables the inclusion of files with the `include` directive.
        """
        ...

    def define_global(self, ident: str, value: Any) -> None:
        r"""
        Defines a global variable and sets its initial value.

        Global variables must be defined before calling [`Compiler::add_source`]
        with some YARA rule that uses the variable. The variable will retain its
        initial value when the [`Rules`] are used for scanning data, however
        each scanner can change the variable's value by calling
        [`crate::Scanner::set_global`].

        The type of `value` must be: bool, str, bytes, int or float.

        # Raises

        [TypeError](https://docs.python.org/3/library/exceptions.html#TypeError)
        if the type of `value` is not one of the supported ones.
        """
        ...

    def new_namespace(self, namespace: str) -> None:
        r"""
        Creates a new namespace.

        Further calls to [`Compiler::add_source`] will put the rules under the
        newly created namespace.
        """
        ...

    def ignore_module(self, module: str) -> None:
        r"""
        Tell the compiler that a YARA module is not supported.

        Import statements for unsupported modules will be ignored without
        errors, but a warning will be issued. Any rule that make use of an
        ignored module will be ignored, while the rest of rules that
        don't rely on that module will be correctly compiled.
        """
        ...

    def build(self) -> Rules:
        r"""
        Builds the source code previously added to the compiler.

        This function returns an instance of [`Rules`] containing all the rules
        previously added with [`Compiler::add_source`] and sets the compiler
        to its initial empty state.
        """
        ...

    def errors(self) -> Any:
        r"""
        Retrieves all errors generated by the compiler.

        This method returns every error encountered during the compilation,
        across all invocations of [`Compiler::add_source`].
        """
        ...

    def warnings(self) -> Any:
        r"""
        Retrieves all warnings generated by the compiler.

        This method returns every warning encountered during the compilation,
        across all invocations of [`Compiler::add_source`].
        """
        ...

    def rule_name_regexp(self, regexp: str) -> None:
        r"""
        Tell the compiler that any rule must match this regular expression or it
        will result in a compiler warning.

        # Raises

        [ValueError](https://docs.python.org/3/library/exceptions.html#ValueError)
        if the regular expression is invalid.
        """
        ...

@final
class ScanOptions:
    r"""
    Optional information for the scan operation.
    """

    def __new__(cls) -> ScanOptions:
        r"""
        Creates a new [`ScanOptions`].
        """
        ...

    def set_module_metadata(self, module: str, metadata: bytes) -> None:
        r"""
        Sets the data associated with a YARA module.
        """
        ...


@final
class Scanner:
    r"""
    Scans data with already compiled YARA rules.

    The scanner receives a set of compiled [`Rules`] and scans data with those
    rules. The same scanner can be used for scanning multiple files or in-memory
    data sequentially, but you need multiple scanners for scanning in parallel.
    """

    def __new__(cls, rules: Rules) -> Scanner:
        r"""
        Creates a new [`Scanner`] with a given set of [`Rules`].
        """
        ...

    def scan(self, data: bytes) -> ScanResults:
        r"""
        Scans in-memory data.
        """
        ...

    def scan_file(self, path: str) -> ScanResults:
        r"""
        Scans a file
        """
        ...

    def scan_with_options(self, data: bytes, options: ScanOptions) -> ScanResults:
        r"""
        Like `scan`, but with options.
        """
        ...

    def scan_file_with_options(self, path: str, options: ScanOptions) -> ScanResults:
        r"""
        Like `scan_file`, but with options.
        """
        ...

    def set_global(self, ident: str, value: Any) -> None:
        r"""
        Sets the value of a global variable.

        The variable must has been previously defined by calling
        [`Compiler::define_global`], and the type it has during the definition
        must match the type of the new value.

        The variable will retain the new value in subsequent scans, unless this
        function is called again for setting a new value.

        The type of `value` must be: `bool`, `str`, `bytes`, `int` or `float`.

        # Raises

        [TypeError](https://docs.python.org/3/library/exceptions.html#TypeError)
        if the type of `value` is not one of the supported ones.
        """
        ...

    def set_timeout(self, seconds: int) -> None:
        r"""
        Sets a timeout for each scan.

        After setting a timeout scans will abort after the specified `seconds`.
        """
        ...

    def max_matches_per_pattern(self, matches: int) -> None:
        r"""
        Sets the maximum number of matches per pattern.

        When some pattern reaches the specified number of `matches` it won't produce more matches.
        """
        ...

    def console_log(self, callback: collections.abc.Callable[[str], Any]) -> None:
        r"""
        Sets a callback that is invoked every time a YARA rule calls the
        `console` module.

        The `callback` function is invoked with a string representing the
        message being logged. The function can print the message to stdout,
        append it to a file, etc. If no callback is set these messages are
        ignored.
        """
        ...

@final
class Formatter:
    r"""
    Formats YARA rules.
    """
    def __new__(
        cls,
        align_metadata: bool = True,
        align_patterns: bool = True,
        indent_section_headers: bool = True,
        indent_section_contents: bool = True,
        indent_spaces: int = 2,
        newline_before_curly_brace: bool = False,
        empty_line_before_section_header: bool = True,
        empty_line_after_section_header: bool = False,
    ) -> Formatter:
        r"""
        Creates a new [`Formatter`].

        `align_metadata` allows for aligning the equals signs in metadata definitions.
        `align_patterns` allows for aligning the equals signs in pattern definitions.
        `indent_section_headers` allows for indenting section headers.
        `indent_section_contents` allows for indenting section contents.
        `indent_spaces` is the number of spaces to use for indentation.
        `newline_before_curly_brace` controls whether a newline is inserted before a curly brace.
        `empty_line_before_section_header` controls whether an empty line is inserted before a section header.
        `empty_line_after_section_header` controls whether an empty line is inserted after a section header.
        """
        ...

    def format(self, input: TextIO, output: TextIO) -> None:
        r"""
        Format a YARA rule
        """
        ...

@final
class Match:
    r"""
    Represents a match found for a pattern.
    """
    @property
    def offset(self) -> int:
        r"""
        Offset where the match occurred.
        """
        ...

    @property
    def length(self) -> int:
        r"""
        Length of the match in bytes.
        """
        ...

    @property
    def xor_key(self) -> Optional[int]:
        r"""
        XOR key used for decrypting the data if the pattern had the xor
        modifier, or None if otherwise.
        """
        ...

@final
class Pattern:
    r"""
    Represents a pattern in a YARA rule.
    """

    @property
    def identifier(self) -> str:
        r"""
        Pattern identifier (e.g: '$a', '$foo').
        """
        ...

    @property
    def matches(self) -> tuple:
        r"""
        Matches found for this pattern.
        """
        ...

@final
class Rule:
    r"""
    Represents a rule that matched while scanning some data.
    """

    @property
    def identifier(self) -> str:
        r"""
        Returns the rule's name.
        """
        ...

    @property
    def namespace(self) -> str:
        r"""
        Returns the rule's namespace.
        """
        ...

    @property
    def tags(self) -> tuple:
        r"""
        Returns the rule's tags.
        """
        ...

    @property
    def metadata(self) -> tuple:
        r"""
        A tuple of pairs `(identifier, value)` with the metadata associated to
        the rule.
        """
        ...

    @property
    def patterns(self) -> tuple:
        r"""
        Patterns defined by the rule.
        """
        ...

@final
class Rules:
    r"""
    A set of YARA rules in compiled form.

    This is the result of [`Compiler::build`].
    """

    def __iter__(self) -> collections.abc.Iterator[Rule]:
        ...

    def scan(self, data: bytes) -> ScanResults:
        r"""
        Scans in-memory data with these rules.
        """
        ...

    def scan_with_options(self, data: bytes, options: ScanOptions) -> ScanResults:
        r"""
        Like `scan`, but with options.
        """
        ...

    def imports(self) -> list[str]:
        r"""
        Returns a list of modules imported by the rules.
        """
        ...

    def serialize_into(self, file: BinaryIO) -> None:
        r"""
        Serializes the rules into a file-like object.
        """
        ...

    @staticmethod
    def deserialize_from(file: BinaryIO) -> Rules:
        r"""
        Deserializes rules from a file-like object.
        """
        ...

@final
class ScanResults:
    r"""
    Results produced by a scan operation.
    """

    @property
    def matching_rules(self) -> Tuple[Rule, ...]:
        r"""
        Rules that matched during the scan.
        """
        ...

    @property
    def module_outputs(self) -> Dict[str, Any]:
        r"""
        Module output from the scan.
        """
        ...

def compile(src: str) -> Rules:
    r"""
    Compiles a YARA source code producing a set of compiled [`Rules`].

    This function allows compiling simple rules that don't depend on external
    variables. For more complex use cases you will need to use a [`Compiler`].
    """
    ...

@final
class Module:
    r"""A YARA-X module."""
    def __new__(cls, name: str) -> Module:
        r"""Creates a new [`Module`] with the given name, which must be a valid YARA-X module name."""
        ...
    def invoke(self, data: str) -> Any:
        r"""Parse the data and collect module metadata."""
        ...
