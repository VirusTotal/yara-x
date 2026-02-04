/*! A Python extension module for YARA-X.

This crate implements a Python module for using YARA-X from Python. It allows
compiling YARA rules and scanning data and files with those rules. Supports
Python 3.8+.

# Usage

```python
import yara_x
rules = yara_x.compile('rule test {strings: $a = "dummy" condition: $a}')
matches = rules.scan(b'some dummy data')
```
 */

#![deny(missing_docs)]
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::marker::PhantomPinned;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;
use std::{io, mem};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use protobuf::MessageDyn;
use pyo3::exceptions::{PyException, PyIOError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{
    PyBool, PyBytes, PyDict, PyFloat, PyInt, PyString, PyStringMethods,
    PyTuple, PyTzInfo,
};
use pyo3::{create_exception, IntoPyObjectExt};
use strum_macros::{Display, EnumString};

use ::yara_x as yrx;
use yara_x_fmt::Indentation;

fn dict_to_json(dict: Bound<PyAny>) -> PyResult<serde_json::Value> {
    static JSON_DUMPS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    let py = dict.py();
    let dumps = JSON_DUMPS.get_or_init(py, || {
        let json_mod = PyModule::import(py, "json").unwrap().unbind();
        json_mod.getattr(py, "dumps").unwrap()
    });
    let json_str: String = dumps.call1(py, (dict,))?.extract(py)?;
    serde_json::from_str(&json_str)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[derive(Debug, Clone, Display, EnumString, PartialEq)]
#[strum(ascii_case_insensitive)]
enum SupportedModules {
    #[cfg(feature = "lnk-module")]
    Lnk,
    #[cfg(feature = "macho-module")]
    Macho,
    #[cfg(feature = "elf-module")]
    Elf,
    #[cfg(feature = "pe-module")]
    Pe,
    #[cfg(feature = "dotnet-module")]
    Dotnet,
    #[cfg(feature = "crx-module")]
    Crx,
    #[cfg(feature = "dex-module")]
    Dex,
}

/// Formats YARA rules.
#[pyclass(unsendable)]
struct Formatter {
    inner: yara_x_fmt::Formatter,
}

#[pymethods]
impl Formatter {
    /// Creates a new [`Formatter`].
    ///
    /// `align_metadata` allows for aligning the equals signs in metadata definitions.
    /// `align_patterns` allows for aligning the equals signs in pattern definitions.
    /// `indent_section_headers` allows for indenting section headers.
    /// `indent_section_contents` allows for indenting section contents.
    /// `indent_spaces` is the number of spaces to use for indentation.
    /// `newline_before_curly_brace` controls whether a newline is inserted before a curly brace.
    /// `empty_line_before_section_header` controls whether an empty line is inserted before a section header.
    /// `empty_line_after_section_header` controls whether an empty line is inserted after a section header.
    #[new]
    #[pyo3(signature = (
        align_metadata = true,
        align_patterns = true,
        indent_section_headers = true,
        indent_section_contents = true,
        indent_spaces = 2,
        newline_before_curly_brace = false,
        empty_line_before_section_header = true,
        empty_line_after_section_header = false
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        align_metadata: bool,
        align_patterns: bool,
        indent_section_headers: bool,
        indent_section_contents: bool,
        indent_spaces: u8,
        newline_before_curly_brace: bool,
        empty_line_before_section_header: bool,
        empty_line_after_section_header: bool,
    ) -> Self {
        Self {
            inner: yara_x_fmt::Formatter::new()
                .align_metadata(align_metadata)
                .align_patterns(align_patterns)
                .indent_section_headers(indent_section_headers)
                .indent_section_contents(indent_section_contents)
                .indentation(if indent_spaces == 0 {
                    Indentation::Tabs
                } else {
                    Indentation::Spaces(indent_spaces as usize)
                })
                .newline_before_curly_brace(newline_before_curly_brace)
                .empty_line_before_section_header(
                    empty_line_before_section_header,
                )
                .empty_line_after_section_header(
                    empty_line_after_section_header,
                ),
        }
    }

    /// Format a YARA rule
    fn format(&self, input: Py<PyAny>, output: Py<PyAny>) -> PyResult<()> {
        self.inner
            .format(PyReader::new(input)?, PyWriter::new(output)?)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;

        Ok(())
    }
}

mod consts {
    use pyo3::prelude::*;
    use pyo3::sync::PyOnceLock;
    use pyo3::types::PyString;
    use pyo3::{intern, Bound, Py, PyResult, Python};

    pub fn read(py: Python<'_>) -> &Bound<'_, PyString> {
        intern!(py, "read")
    }

    pub fn write(py: Python<'_>) -> &Bound<'_, PyString> {
        intern!(py, "write")
    }

    pub fn flush(py: Python<'_>) -> &Bound<'_, PyString> {
        intern!(py, "flush")
    }

    pub fn text_io_base(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
        static INSTANCE: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

        INSTANCE
            .get_or_try_init(py, || {
                let io = PyModule::import(py, "io")?;
                let cls = io.getattr("TextIOBase")?;
                Ok(cls.unbind())
            })
            .map(|x| x.bind(py))
    }
}

struct PyReader {
    obj: Py<PyAny>,
    is_text_io: bool,
}

impl PyReader {
    pub fn new(obj: Py<PyAny>) -> PyResult<Self> {
        Python::attach(|py| {
            let obj_bound = obj.bind(py);

            if !obj_bound.hasattr(consts::read(py))? {
                return Err(PyTypeError::new_err(
                    "object does not have a .read() method.",
                ));
            }

            let is_text_io =
                obj_bound.is_instance(consts::text_io_base(py)?)?;

            Ok(Self { obj, is_text_io })
        })
    }
}

impl Read for PyReader {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        Python::attach(|py| {
            let data =
                self.obj.call_method1(py, consts::read(py), (buf.len(),))?;

            if self.is_text_io {
                let bytes = data.extract::<Cow<str>>(py).unwrap();
                buf.write_all(bytes.as_bytes())?;
                Ok(bytes.len())
            } else {
                let bytes = data.extract::<Cow<[u8]>>(py).unwrap();
                buf.write_all(bytes.as_ref())?;
                Ok(bytes.len())
            }
        })
    }
}

struct PyWriter {
    obj: Py<PyAny>,
    is_text_io: bool,
}

impl PyWriter {
    pub fn new(obj: Py<PyAny>) -> PyResult<Self> {
        Python::attach(|py| {
            let obj_bound = obj.bind(py);

            if !obj_bound.hasattr(consts::write(py))? {
                return Err(PyTypeError::new_err(
                    "object does not have a .write() method.",
                ));
            }

            let is_text_io =
                obj_bound.is_instance(consts::text_io_base(py)?)?;

            Ok(Self { obj, is_text_io })
        })
    }
}

impl Write for PyWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Python::attach(|py| {
            let arg = if self.is_text_io {
                let s = std::str::from_utf8(buf).expect(
                    "tried to write non-utf8 data to a TextIO object.",
                );
                PyString::new(py, s).into_any()
            } else {
                PyBytes::new(py, buf).into_any()
            };

            let n = self.obj.call_method1(py, consts::write(py), (arg,))?;

            n.extract(py).map_err(io::Error::from)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Python::attach(|py| {
            self.obj.call_method0(py, consts::flush(py))?;
            Ok(())
        })
    }
}

#[pyclass]
struct Module {
    _module: SupportedModules,
}

#[pymethods]
impl Module {
    /// Creates a new [`Module`].
    ///
    /// Type of module must be one of [`SupportedModules`]
    #[new]
    fn new(name: &str) -> PyResult<Self> {
        Ok(Self {
            _module: SupportedModules::from_str(name).map_err(|_| {
                PyValueError::new_err(format!("{name} not a supported module"))
            })?,
        })
    }

    /// Invoke the module with provided data.
    ///
    /// Returns None if the module didn't produce any output for the given data.
    #[allow(unreachable_code, unused_variables, unreachable_patterns)]
    fn invoke<'py>(
        &'py self,
        py: Python<'py>,
        data: &[u8],
    ) -> PyResult<Bound<'py, PyAny>> {
        let module_output: Option<Box<dyn protobuf::MessageDyn>> =
            match self._module {
                #[cfg(feature = "macho-module")]
                SupportedModules::Macho => {
                    yrx::mods::invoke_dyn::<yrx::mods::Macho>(data)
                }
                #[cfg(feature = "lnk-module")]
                SupportedModules::Lnk => {
                    yrx::mods::invoke_dyn::<yrx::mods::Lnk>(data)
                }
                #[cfg(feature = "elf-module")]
                SupportedModules::Elf => {
                    yrx::mods::invoke_dyn::<yrx::mods::ELF>(data)
                }
                #[cfg(feature = "pe-module")]
                SupportedModules::Pe => {
                    yrx::mods::invoke_dyn::<yrx::mods::PE>(data)
                }
                #[cfg(feature = "dotnet-module")]
                SupportedModules::Dotnet => {
                    yrx::mods::invoke_dyn::<yrx::mods::Dotnet>(data)
                }
                #[cfg(feature = "crx-module")]
                SupportedModules::Crx => {
                    yrx::mods::invoke_dyn::<yrx::mods::Crx>(data)
                }
                #[cfg(feature = "dex-module")]
                SupportedModules::Dex => {
                    yrx::mods::invoke_dyn::<yrx::mods::Dex>(data)
                }
                _ => return Ok(py.None().into_bound(py)),
            };

        let module_output = match module_output {
            Some(output) => output,
            None => return Ok(py.None().into_bound(py)),
        };

        proto_to_json(py, module_output.as_ref())
    }
}

/// Returns the names of the supported modules.
///
/// These are the modules that can be used in `import` statements in your
/// rules.
#[pyfunction]
fn module_names<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
    PyTuple::new(py, yrx::mods::module_names().collect::<Vec<_>>())
}

/// Compiles a YARA source code producing a set of compiled [`Rules`].
///
/// This function allows compiling simple rules that don't depend on external
/// variables. For more complex use cases you will need to use a [`Compiler`].
#[pyfunction]
fn compile(src: &str) -> PyResult<Rules> {
    let rules = yrx::compile(src)
        .map_err(|err| CompileError::new_err(err.to_string()))?;

    Ok(Rules::new(rules))
}

/// Compiles YARA source code producing a set of compiled [`Rules`].
#[pyclass(unsendable)]
struct Compiler {
    inner: yrx::Compiler<'static>,
    relaxed_re_syntax: bool,
    error_on_slow_pattern: bool,
    includes_enabled: bool,
}

impl Compiler {
    fn new_inner(
        relaxed_re_syntax: bool,
        error_on_slow_pattern: bool,
    ) -> yrx::Compiler<'static> {
        let mut compiler = yrx::Compiler::new();
        compiler.relaxed_re_syntax(relaxed_re_syntax);
        compiler.error_on_slow_pattern(error_on_slow_pattern);
        compiler
    }
}

#[pymethods]
impl Compiler {
    /// Creates a new [`Compiler`].
    ///
    /// The `relaxed_re_syntax` argument controls whether the compiler should
    /// adopt a more relaxed syntax check for regular expressions, allowing
    /// constructs that YARA-X doesn't accept by default.
    ///
    /// YARA-X enforces stricter regular expression syntax compared to YARA.
    /// For instance, YARA accepts invalid escape sequences and treats them
    /// as literal characters (e.g., \R is interpreted as a literal 'R'). It
    /// also allows some special characters to appear unescaped, inferring
    /// their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
    /// literal, but in `/foo{0,1}bar/` they form the repetition operator
    /// `{0,1}`).
    ///
    /// The `error_on_slow_pattern` argument tells the compiler to treat slow
    /// patterns as errors, instead of warnings.
    #[new]
    #[pyo3(signature = (relaxed_re_syntax=false, error_on_slow_pattern=false, includes_enabled=true)
    )]
    fn new(
        relaxed_re_syntax: bool,
        error_on_slow_pattern: bool,
        includes_enabled: bool,
    ) -> Self {
        let mut compiler = Self {
            inner: Self::new_inner(relaxed_re_syntax, error_on_slow_pattern),
            relaxed_re_syntax,
            error_on_slow_pattern,
            includes_enabled,
        };
        compiler.inner.enable_includes(includes_enabled);
        compiler
    }

    /// Specify a regular expression that the compiler will enforce upon each
    /// rule name. Any rule which has a name which does not match this regex
    /// will return an InvalidRuleName warning.
    ///
    /// If the regexp does not compile a ValueError is returned.
    #[pyo3(signature = (regexp))]
    fn rule_name_regexp(&mut self, regexp: &str) -> PyResult<()> {
        let linter = yrx::linters::rule_name(regexp)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        self.inner.add_linter(linter);
        Ok(())
    }

    /// Adds a YARA source code to be compiled.
    ///
    /// This function may be invoked multiple times to add several sets of YARA
    /// rules before calling [`Compiler::build`]. If the rules provided in
    /// `src` contain errors that prevent compilation, the function will raise
    /// an exception with the first error encountered. Additionally, the
    /// compiler will store this error, along with any others discovered during
    /// compilation, which can be accessed using [`Compiler::errors`].
    ///
    /// Even if a previous invocation resulted in a compilation error, you can
    /// continue calling this function. In such cases, any rules that failed to
    /// compile will not be included in the final compiled set.
    ///
    /// The optional parameter `origin` allows to specify the origin of the
    /// source code. This usually receives the path of the file from where the
    /// code was read, but it can be any arbitrary string that conveys information
    /// about the source code's origin.
    #[pyo3(signature = (src, origin=None))]
    fn add_source(
        &mut self,
        src: &str,
        origin: Option<String>,
    ) -> PyResult<()> {
        let mut src = yrx::SourceCode::from(src);

        if let Some(origin) = origin.as_ref() {
            src = src.with_origin(origin)
        }

        self.inner
            .add_source(src)
            .map_err(|err| CompileError::new_err(err.to_string()))?;

        Ok(())
    }

    /// Adds a directory to the list of directories where the compiler should
    /// look for included files.
    ///
    /// When an `include` statement is found, the compiler looks for the included
    /// file in the directories added with this function, in the order they were
    /// added.
    ///
    /// If this function is not called, the compiler will only look for included
    /// files in the current directory.
    ///
    /// Use [Compiler::enable_includes] for controlling whether include statements
    /// are allowed or not.
    ///
    /// # Example
    ///
    /// ```
    /// import yara_x
    /// compiler = yara_x.Compiler()
    /// compiler.add_include_dir("/path/to/rules")
    /// compiler.add_include_dir("/another/path")
    /// ```
    fn add_include_dir(&mut self, dir: &str) {
        self.inner.add_include_dir(dir);
    }

    /// Defines a global variable and sets its initial value.
    ///
    /// Global variables must be defined before calling [`Compiler::add_source`]
    /// with some YARA rule that uses the variable. The variable will retain its
    /// initial value when the [`Rules`] are used for scanning data, however
    /// each scanner can change the variable's value by calling
    /// [`crate::Scanner::set_global`].
    ///
    /// The type of `value` must be: bool, str, bytes, int or float.
    ///
    /// # Raises
    ///
    /// [TypeError](https://docs.python.org/3/library/exceptions.html#TypeError)
    /// if the type of `value` is not one of the supported ones.
    fn define_global(
        &mut self,
        ident: &str,
        value: Bound<PyAny>,
    ) -> PyResult<()> {
        let result = if value.is_exact_instance_of::<PyBool>() {
            self.inner.define_global(ident, value.extract::<bool>()?)
        } else if value.is_exact_instance_of::<PyString>() {
            self.inner.define_global(ident, value.extract::<String>()?)
        } else if value.is_exact_instance_of::<PyBytes>() {
            self.inner.define_global(ident, value.extract::<&[u8]>()?)
        } else if value.is_exact_instance_of::<PyInt>() {
            self.inner.define_global(ident, value.extract::<i64>()?)
        } else if value.is_exact_instance_of::<PyFloat>() {
            self.inner.define_global(ident, value.extract::<f64>()?)
        } else if value.is_exact_instance_of::<PyDict>() {
            self.inner.define_global(ident, dict_to_json(value)?)
        } else {
            return Err(PyTypeError::new_err(format!(
                "unsupported variable type `{}`",
                value.get_type()
            )));
        };

        result.map_err(|err| PyValueError::new_err(err.to_string()))?;

        Ok(())
    }

    /// Creates a new namespace.
    ///
    /// Further calls to [`Compiler::add_source`] will put the rules under the
    /// newly created namespace.
    fn new_namespace(&mut self, namespace: &str) {
        self.inner.new_namespace(namespace);
    }

    /// Tell the compiler that a YARA module is not supported.
    ///
    /// Import statements for ignored modules will be ignored without errors,
    /// but a warning will be issued. Any rule that makes use of an ignored
    /// module will be also ignored, while the rest of the rules that don't
    /// rely on that module will be correctly compiled.
    fn ignore_module(&mut self, module: &str) {
        self.inner.ignore_module(module);
    }

    /// Enables or disables the inclusion of files with the `include` directive.
    ///
    /// When includes are disabled, any `include` directive encountered in the
    /// source code will be treated as an error. By default, includes are enabled.
    ///
    /// # Example
    ///
    /// ```python
    /// import yara_x
    ///
    /// compiler = yara_x.Compiler()
    /// compiler.enable_includes(False)  # Disable includes
    /// ```
    fn enable_includes(&mut self, yes: bool) {
        self.includes_enabled = yes;
        self.inner.enable_includes(yes);
    }

    /// Builds the source code previously added to the compiler.
    ///
    /// This function returns an instance of [`Rules`] containing all the rules
    /// previously added with [`Compiler::add_source`] and sets the compiler
    /// to its initial empty state.
    fn build(&mut self) -> Rules {
        let compiler = mem::replace(
            &mut self.inner,
            Self::new_inner(
                self.relaxed_re_syntax,
                self.error_on_slow_pattern,
            ),
        );
        Rules::new(compiler.build())
    }

    /// Retrieves all errors generated by the compiler.
    ///
    /// This method returns every error encountered during the compilation,
    /// across all invocations of [`Compiler::add_source`].
    fn errors<'py>(&'py self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let json = PyModule::import(py, "json")?;
        let json_loads = json.getattr("loads")?;
        let errors_json = serde_json::to_string_pretty(&self.inner.errors());
        let errors_json = errors_json
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        json_loads.call((errors_json,), None)
    }

    /// Retrieves all warnings generated by the compiler.
    ///
    /// This method returns every warning encountered during the compilation,
    /// across all invocations of [`Compiler::add_source`].
    fn warnings<'py>(
        &'py self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json = PyModule::import(py, "json")?;
        let json_loads = json.getattr("loads")?;
        let warnings_json =
            serde_json::to_string_pretty(&self.inner.warnings());
        let warnings_json = warnings_json
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        json_loads.call((warnings_json,), None)
    }
}

/// Optional information for the scan operation.
#[pyclass]
struct ScanOptions {
    module_metadata: HashMap<String, Vec<u8>>,
}

impl<'a> From<&'a ScanOptions> for yrx::ScanOptions<'a> {
    fn from(options: &'a ScanOptions) -> Self {
        let mut result = yrx::ScanOptions::new();
        for (module_name, metadata) in &options.module_metadata {
            result = result.set_module_metadata(
                module_name.as_str(),
                metadata.as_slice(),
            );
        }
        result
    }
}

#[pymethods]
impl ScanOptions {
    /// Creates a new [`ScanOptions`].
    #[new]
    fn new() -> Self {
        Self { module_metadata: HashMap::new() }
    }

    /// Sets the data associated with a YARA module.
    ///
    /// When scanning a file, YARA modules may require additional data that is
    /// not present in the file itself. For instance, the `cuckoo` module may
    /// need a report from Cuckoo sandbox with information about the file being
    /// scanned.
    ///
    /// This function is used for providing that data to the modules. The data
    /// is specific to the module, and each module expects a different data
    /// structure. The data is passed as raw bytes that the module is responsible
    /// to decode accordingly.
    fn set_module_metadata(
        &mut self,
        module: &str,
        metadata: Bound<PyBytes>,
    ) -> PyResult<()> {
        let metadata = metadata.extract::<Vec<u8>>()?;
        self.module_metadata.insert(module.to_string(), metadata);
        Ok(())
    }
}

/// Scans data with already compiled YARA rules.
///
/// The scanner receives a set of compiled Rules and scans data with those
/// rules. The same scanner can be used for scanning multiple files or
/// in-memory data sequentially, but you need multiple scanners for scanning
/// in parallel.
#[pyclass(unsendable)]
struct Scanner {
    // The only purpose of this field is making sure that the `Rules` object
    // is not freed while the `Scanner` object is still around. This reference
    // to the `Rules` object will keep it alive during the scanner lifetime.
    //
    // We need the `Rules` object alive because the `yrx::Scanner` holds a
    // reference to the `yrx::Rules` contained in `Rules`. This reference
    // is obtained in an unsafe manner from a pointer, for that reason the
    // `yrx::Rules` are pinned, so that they are not moved from their
    // original location and the reference remains valid.
    _rules: Py<Rules>,
    inner: yrx::Scanner<'static>,
}

#[pymethods]
impl Scanner {
    /// Creates a new [`Scanner`] with a given set of [`Rules`].
    #[new]
    fn new(rules: Py<Rules>) -> Self {
        Python::attach(|py| {
            let rules_ref: &'static yrx::Rules = {
                let rules = rules.borrow(py);
                let rules_ptr: *const yrx::Rules = &rules.deref().inner.rules;
                unsafe { &*rules_ptr }
            };
            Self { _rules: rules, inner: yrx::Scanner::new(rules_ref) }
        })
    }

    /// Sets the value of a global variable.
    ///
    /// The variable must has been previously defined by calling
    /// [`Compiler::define_global`], and the type it has during the definition
    /// must match the type of the new value.
    ///
    /// The variable will retain the new value in subsequent scans, unless this
    /// function is called again for setting a new value.
    ///
    /// The type of `value` must be: `bool`, `str`, `bytes`, `int` or `float`.
    ///
    /// # Raises
    ///
    /// [TypeError](https://docs.python.org/3/library/exceptions.html#TypeError)
    /// if the type of `value` is not one of the supported ones.
    fn set_global(
        &mut self,
        ident: &str,
        value: Bound<PyAny>,
    ) -> PyResult<()> {
        let result = if value.is_exact_instance_of::<PyBool>() {
            self.inner.set_global(ident, value.extract::<bool>()?)
        } else if value.is_exact_instance_of::<PyString>() {
            self.inner.set_global(ident, value.extract::<String>()?)
        } else if value.is_exact_instance_of::<PyBytes>() {
            self.inner.set_global(ident, value.extract::<&[u8]>()?)
        } else if value.is_exact_instance_of::<PyInt>() {
            self.inner.set_global(ident, value.extract::<i64>()?)
        } else if value.is_exact_instance_of::<PyFloat>() {
            self.inner.set_global(ident, value.extract::<f64>()?)
        } else if value.is_exact_instance_of::<PyDict>() {
            self.inner.set_global(ident, dict_to_json(value)?)
        } else {
            return Err(PyTypeError::new_err(format!(
                "unsupported variable type `{}`",
                value.get_type()
            )));
        };

        result.map_err(|err| PyValueError::new_err(err.to_string()))?;

        Ok(())
    }

    /// Sets a timeout for each scan.
    ///
    /// After setting a timeout scans will abort after the specified `seconds`.
    fn set_timeout(&mut self, seconds: u64) {
        self.inner.set_timeout(Duration::from_secs(seconds));
    }

    /// Sets the maximum number of matches per pattern.
    ///
    /// When some pattern reaches the specified number of `matches` it won't produce more matches.
    fn max_matches_per_pattern(&mut self, matches: usize) {
        self.inner.max_matches_per_pattern(matches);
    }

    /// Sets a callback that is invoked every time a YARA rule calls the
    /// `console` module.
    ///
    /// The `callback` function is invoked with a string representing the
    /// message being logged. The function can print the message to stdout,
    /// append it to a file, etc. If no callback is set these messages are
    /// ignored.
    fn console_log(&mut self, callback: Py<PyAny>) -> PyResult<()> {
        if !Python::attach(|py| callback.bind(py).is_callable()) {
            return Err(PyValueError::new_err("callback is not callable"));
        }
        self.inner.console_log(move |msg| {
            let _ = Python::attach(|py| -> PyResult<Py<PyAny>> {
                callback.call1(py, (msg,))
            });
        });
        Ok(())
    }

    /// Scans in-memory data.
    fn scan(&mut self, data: &[u8]) -> PyResult<Py<ScanResults>> {
        let results = self.inner.scan(data).map_err(map_scan_err)?;
        Python::attach(|py| scan_results_to_py(py, results))
    }

    /// Like [`Scanner::scan`], but allows to specify additional scan options.
    fn scan_with_options(
        &mut self,
        data: &[u8],
        options: &ScanOptions,
    ) -> PyResult<Py<ScanResults>> {
        let results = self
            .inner
            .scan_with_options(data, yrx::ScanOptions::from(options))
            .map_err(map_scan_err)?;
        Python::attach(|py| scan_results_to_py(py, results))
    }

    /// Scans a file.
    fn scan_file(&mut self, path: PathBuf) -> PyResult<Py<ScanResults>> {
        let results = self.inner.scan_file(path).map_err(map_scan_err)?;
        Python::attach(|py| scan_results_to_py(py, results))
    }

    /// Like [`Scanner::scan_file`], but allows to specify additional scan options.
    fn scan_file_with_options(
        &mut self,
        path: PathBuf,
        options: &ScanOptions,
    ) -> PyResult<Py<ScanResults>> {
        let results = self
            .inner
            .scan_file_with_options(path, yrx::ScanOptions::from(options))
            .map_err(map_scan_err)?;
        Python::attach(|py| scan_results_to_py(py, results))
    }
}

/// Results produced by a scan operation.
#[pyclass]
struct ScanResults {
    /// Vector that contains all the rules that matched during the scan.
    matching_rules: Py<PyTuple>,
    /// Dictionary where keys are module names and values are other
    /// dictionaries with the information produced by the corresponding module.
    module_outputs: Py<PyDict>,
}

#[pymethods]
impl ScanResults {
    #[getter]
    /// Rules that matched during the scan.
    fn matching_rules(&self) -> Py<PyTuple> {
        Python::attach(|py| self.matching_rules.clone_ref(py))
    }

    #[getter]
    /// Module output from the scan.
    fn module_outputs<'py>(
        &'py self,
        py: Python<'py>,
    ) -> &'py Bound<'py, PyDict> {
        self.module_outputs.bind(py)
    }
}

/// Represents a rule that matched while scanning some data.
#[pyclass]
struct Rule {
    identifier: String,
    namespace: String,
    tags: Py<PyTuple>,
    metadata: Py<PyTuple>,
    patterns: Py<PyTuple>,
}

#[pymethods]
impl Rule {
    #[getter]
    /// Returns the rule's name.
    fn identifier(&self) -> &str {
        self.identifier.as_str()
    }

    /// Returns the rule's namespace.
    #[getter]
    fn namespace(&self) -> &str {
        self.namespace.as_str()
    }

    /// Returns the rule's tags.
    #[getter]
    fn tags(&self) -> Py<PyTuple> {
        Python::attach(|py| self.tags.clone_ref(py))
    }

    /// A tuple of pairs `(identifier, value)` with the metadata associated to
    /// the rule.
    #[getter]
    fn metadata(&self) -> Py<PyTuple> {
        Python::attach(|py| self.metadata.clone_ref(py))
    }

    /// Patterns defined by the rule.
    #[getter]
    fn patterns(&self) -> Py<PyTuple> {
        Python::attach(|py| self.patterns.clone_ref(py))
    }
}

/// Represents a pattern in a YARA rule.
#[pyclass]
struct Pattern {
    identifier: String,
    matches: Py<PyTuple>,
}

#[pymethods]
impl Pattern {
    /// Pattern identifier (e.g: '$a', '$foo').
    #[getter]
    fn identifier(&self) -> &str {
        self.identifier.as_str()
    }

    /// Matches found for this pattern.
    #[getter]
    fn matches(&self) -> Py<PyTuple> {
        Python::attach(|py| self.matches.clone_ref(py))
    }
}

/// Represents a match found for a pattern.
#[pyclass]
struct Match {
    /// Offset within the scanned data where the match occurred.
    offset: usize,
    /// Length of the match.
    length: usize,
    /// For patterns that have the `xor` modifier, contains the XOR key that
    /// applied to matching data. For any other pattern will be `None`.
    xor_key: Option<u8>,
}

#[pymethods]
impl Match {
    /// Offset where the match occurred.
    #[getter]
    fn offset(&self) -> usize {
        self.offset
    }

    /// Length of the match in bytes.
    #[getter]
    fn length(&self) -> usize {
        self.length
    }

    /// XOR key used for decrypting the data if the pattern had the xor
    /// modifier, or None if otherwise.
    #[getter]
    fn xor_key(&self) -> Option<u8> {
        self.xor_key
    }
}

/// A set of YARA rules in compiled form.
///
/// This is the result of [`Compiler::build`].
#[pyclass]
struct Rules {
    inner: Pin<Box<PinnedRules>>,
}

struct PinnedRules {
    rules: yrx::Rules,
    _pinned: PhantomPinned,
}

impl Rules {
    fn new(rules: yrx::Rules) -> Self {
        Rules {
            inner: Box::pin(PinnedRules { rules, _pinned: PhantomPinned }),
        }
    }
}

#[pyclass(unsendable)]
struct RulesIter {
    iter: Box<dyn Iterator<Item = yrx::Rule<'static, 'static>> + Send>,
    // Keep a reference to Rules to keep it alive.
    _rules: Py<Rules>,
}

#[pymethods]
impl RulesIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>) -> PyResult<Option<Py<Rule>>> {
        let py = slf.py();
        match slf.iter.next() {
            Some(rule) => Ok(Some(rule_to_py(py, rule)?)),
            None => Ok(None),
        }
    }
}

#[pymethods]
impl Rules {
    /// Scans in-memory data with these rules.
    fn scan(&self, data: &[u8]) -> PyResult<Py<ScanResults>> {
        let mut scanner = yrx::Scanner::new(&self.inner.rules);
        let results = scanner
            .scan(data)
            .map_err(|err| ScanError::new_err(err.to_string()))?;
        Python::attach(|py| scan_results_to_py(py, results))
    }

    /// Scans in-memory data with these rules.
    fn scan_with_options(
        &self,
        data: &[u8],
        options: &ScanOptions,
    ) -> PyResult<Py<ScanResults>> {
        let mut scanner = yrx::Scanner::new(&self.inner.rules);
        let results = scanner
            .scan_with_options(data, yrx::ScanOptions::from(options))
            .map_err(|err| ScanError::new_err(err.to_string()))?;
        Python::attach(|py| scan_results_to_py(py, results))
    }

    /// Serializes the rules into a file-like object.
    fn serialize_into(&self, file: Py<PyAny>) -> PyResult<()> {
        self.inner
            .rules
            .serialize_into(PyWriter::new(file)?)
            .map_err(|err| PyIOError::new_err(err.to_string()))
    }

    /// Deserializes rules from a file-like object.
    #[staticmethod]
    fn deserialize_from(file: Py<PyAny>) -> PyResult<Py<Rules>> {
        let rules = yrx::Rules::deserialize_from(PyReader::new(file)?)
            .map_err(|err| PyIOError::new_err(err.to_string()))?;

        Python::attach(|py| Py::new(py, Rules::new(rules)))
    }

    /// Returns an iterator over the rules.
    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<Py<RulesIter>> {
        let py = slf.py();

        let rules: &'static yrx::Rules =
            unsafe { mem::transmute(&slf.inner.rules) };

        let rules_iter =
            RulesIter { iter: Box::new(rules.iter()), _rules: slf.into() };

        Py::new(py, rules_iter)
    }

    /// Returns a list of modules imported by the rules.
    fn imports(&self) -> PyResult<Vec<&str>> {
        Ok(self.inner.rules.imports().collect())
    }
}

fn scan_results_to_py(
    py: Python,
    scan_results: yrx::ScanResults,
) -> PyResult<Py<ScanResults>> {
    let matching_rules = scan_results
        .matching_rules()
        .map(|rule| rule_to_py(py, rule))
        .collect::<PyResult<Vec<_>>>()?;

    let module_outputs = PyDict::new(py);
    let outputs = scan_results.module_outputs();

    if outputs.len() > 0 {
        for (module, output) in outputs {
            module_outputs.set_item(module, proto_to_json(py, output)?)?;
        }
    }

    Py::new(
        py,
        ScanResults {
            matching_rules: PyTuple::new(py, matching_rules)?.unbind(),
            module_outputs: module_outputs.into(),
        },
    )
}

fn rule_to_py(py: Python, rule: yrx::Rule) -> PyResult<Py<Rule>> {
    Py::new(
        py,
        Rule {
            identifier: rule.identifier().to_string(),
            namespace: rule.namespace().to_string(),
            tags: PyTuple::new(py, rule.tags().map(|tag| tag.identifier()))?
                .unbind(),
            metadata: PyTuple::new(
                py,
                rule.metadata()
                    .map(|(ident, value)| metadata_to_py(py, ident, value)),
            )?
            .unbind(),
            patterns: PyTuple::new(
                py,
                rule.patterns()
                    .map(|pattern| pattern_to_py(py, pattern))
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .unbind(),
        },
    )
}

fn metadata_to_py(
    py: Python,
    ident: &str,
    metadata: yrx::MetaValue,
) -> Py<PyTuple> {
    let value = match metadata {
        yrx::MetaValue::Integer(v) => v.into_py_any(py),
        yrx::MetaValue::Float(v) => v.into_py_any(py),
        yrx::MetaValue::Bool(v) => v.into_py_any(py),
        yrx::MetaValue::String(v) => v.into_py_any(py),
        yrx::MetaValue::Bytes(v) => v.into_py_any(py),
    }
    .unwrap();

    PyTuple::new(py, [ident.into_py_any(py).unwrap(), value]).unwrap().unbind()
}

fn pattern_to_py(py: Python, pattern: yrx::Pattern) -> PyResult<Py<Pattern>> {
    Py::new(
        py,
        Pattern {
            identifier: pattern.identifier().to_string(),
            matches: PyTuple::new(
                py,
                pattern
                    .matches()
                    .map(|match_| match_to_py(py, match_))
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .unbind(),
        },
    )
}

fn match_to_py(py: Python, match_: yrx::Match) -> PyResult<Py<Match>> {
    Py::new(
        py,
        Match {
            offset: match_.range().start,
            length: match_.range().len(),
            xor_key: match_.xor_key(),
        },
    )
}

/// Decodes the JSON output generated by YARA modules and converts it
/// into a native Python dictionary.
///
/// YARA module outputs often include values that require special handling.
/// In particular, raw byte strings—since they cannot be directly represented
/// in JSON—are encoded as base64 and wrapped in an object that includes
/// both the encoded value and metadata about the encoding. For example:
///
/// ```json
/// "my_bytes_field": {
///   "encoding": "base64",
///   "value": "dGhpcyBpcyB0aGUgb3JpZ2luYWwgdmFsdWU="
/// }
/// ```
///
/// This decoder identifies such structures, decodes the base64-encoded content,
/// and returns the result as a Python `bytes` object, preserving the original
/// binary data.
#[pyclass]
struct JsonDecoder {
    fromtimestamp: Py<PyAny>,
}

#[pymethods]
impl JsonDecoder {
    #[staticmethod]
    fn new() -> Self {
        JsonDecoder {
            fromtimestamp: Python::attach(|py| {
                PyModule::import(py, "datetime")
                    .unwrap()
                    .getattr("datetime")
                    .unwrap()
                    .getattr("fromtimestamp")
                    .unwrap()
                    .unbind()
            }),
        }
    }

    fn __call__<'py>(
        &self,
        py: Python<'py>,
        dict: Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(encoding) = dict
            .get_item("encoding")?
            .as_ref()
            .and_then(|encoding| encoding.cast::<PyString>().ok())
        {
            let value = match dict.get_item("value")? {
                Some(value) => value,
                None => return Ok(dict.into_any()),
            };

            if encoding == "base64" {
                BASE64_STANDARD
                    .decode(value.cast::<PyString>()?.to_cow()?.as_bytes())
                    .expect("decoding base64")
                    .into_bound_py_any(py)
            } else if encoding == "timestamp" {
                let kwargs = PyDict::new(py);
                kwargs.set_item("tz", PyTzInfo::utc(py)?)?;
                self.fromtimestamp
                    .call(py, (value,), Some(&kwargs))?
                    .into_bound_py_any(py)
            } else {
                Ok(dict.into_any())
            }
        } else {
            Ok(dict.into_any())
        }
    }
}

fn proto_to_json<'py>(
    py: Python<'py>,
    proto: &dyn MessageDyn,
) -> PyResult<Bound<'py, PyAny>> {
    let mut module_output_json = Vec::new();

    let mut serializer =
        yara_x_proto_json::Serializer::new(&mut module_output_json);

    serializer
        .serialize(proto)
        .expect("unable to serialize JSON produced by module");

    let json = PyModule::import(py, "json")?;
    let json_loads = json.getattr("loads")?;

    let kwargs = PyDict::new(py);

    // The `object_hook` argument for `json.loads` allows to pass a callable
    // that can transform JSON objects on the fly. This is used in order to
    // decode some types that are not directly representable in JSON. See the
    // documentation for JsonDecode for details.
    kwargs.set_item("object_hook", JsonDecoder::new())?;
    // By default, json.loads doesn't allow control character (\t, \n, etc)
    // in strings, we need to set strict=False to allow them.
    // https://github.com/VirusTotal/yara-x/issues/365
    kwargs.set_item("strict", false)?;

    json_loads.call((module_output_json,), Some(&kwargs))
}

create_exception!(
    yara_x,
    CompileError,
    PyException,
    "Exception raised when compilation fails"
);

create_exception!(
    yara_x,
    TimeoutError,
    PyException,
    "Exception raised when a timeout occurs during a scan"
);

create_exception!(
    yara_x,
    ScanError,
    PyException,
    "Exception raised when scanning fails"
);

fn map_scan_err(err: yrx::errors::ScanError) -> PyErr {
    match err {
        yrx::errors::ScanError::Timeout => TimeoutError::new_err("timeout"),
        err => ScanError::new_err(err.to_string()),
    }
}

/// Python module for compiling YARA rules and scanning data with them.
///
/// Usage:
///
/// >>> import yara_x
/// >>> rules = yara_x.compile('rule test {strings: $a = "dummy" condition: $a}')
/// >>> matches = rules.scan(b'some dummy data')
/// ```
#[pymodule]
fn yara_x(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("CompileError", m.py().get_type::<CompileError>())?;
    m.add("TimeoutError", m.py().get_type::<TimeoutError>())?;
    m.add("ScanError", m.py().get_type::<ScanError>())?;
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_function(wrap_pyfunction!(module_names, m)?)?;
    m.add_class::<Rules>()?;
    m.add_class::<Scanner>()?;
    m.add_class::<ScanOptions>()?;
    m.add_class::<ScanResults>()?;
    m.add_class::<Compiler>()?;
    m.add_class::<Rule>()?;
    m.add_class::<Pattern>()?;
    m.add_class::<Match>()?;
    m.add_class::<Formatter>()?;
    m.add_class::<Module>()?;
    m.gil_used(false)?;
    Ok(())
}
