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

use std::marker::PhantomPinned;
use std::mem;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use protobuf_json_mapping::print_to_string as proto_to_json;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyIOError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{
    PyBool, PyBytes, PyDict, PyFloat, PyInt, PyString, PyTuple,
};
use pyo3_file::PyFileLikeObject;

use ::yara_x as yrx;

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
}

impl Compiler {
    fn new_inner(
        relaxed_re_syntax: bool,
        error_on_slow_pattern: bool,
    ) -> yrx::Compiler<'static> {
        let mut compiler = yrx::Compiler::new();
        if relaxed_re_syntax {
            compiler.relaxed_re_syntax(true);
        }
        if error_on_slow_pattern {
            compiler.error_on_slow_pattern(true);
        }
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
    #[pyo3(signature = (*, relaxed_re_syntax=false, error_on_slow_pattern=false))]
    fn new(relaxed_re_syntax: bool, error_on_slow_pattern: bool) -> Self {
        Self {
            inner: Self::new_inner(relaxed_re_syntax, error_on_slow_pattern),
            relaxed_re_syntax,
            error_on_slow_pattern,
        }
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
    /// Import statements for unsupported modules will be ignored without
    /// errors, but a warning will be issued. Any rule that make use of an
    /// ignored module will be ignored, while the rest of rules that
    /// don't rely on that module will be correctly compiled.
    fn ignore_module(&mut self, module: &str) {
        self.inner.ignore_module(module);
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
        let json = PyModule::import_bound(py, "json")?;
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
        let json = PyModule::import_bound(py, "json")?;
        let json_loads = json.getattr("loads")?;
        let warnings_json =
            serde_json::to_string_pretty(&self.inner.warnings());
        let warnings_json = warnings_json
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        json_loads.call((warnings_json,), None)
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
        Python::with_gil(|py| {
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

    /// Sets a callback that is invoked every time a YARA rule calls the
    /// `console` module.
    ///
    /// The `callback` function is invoked with a string representing the
    /// message being logged. The function can print the message to stdout,
    /// append it to a file, etc. If no callback is set these messages are
    /// ignored.
    fn console_log(&mut self, callback: PyObject) -> PyResult<()> {
        if !Python::with_gil(|py| callback.bind(py).is_callable()) {
            return Err(PyValueError::new_err("callback is not callable"));
        }
        self.inner.console_log(move |msg| {
            let _ = Python::with_gil(|py| -> PyResult<PyObject> {
                callback.call1(py, (msg,))
            });
        });
        Ok(())
    }

    /// Scans in-memory data.
    fn scan(&mut self, data: &[u8]) -> PyResult<Py<ScanResults>> {
        Python::with_gil(|py| {
            scan_results_to_py(
                py,
                self.inner.scan(data).map_err(map_scan_err)?,
            )
        })
    }

    /// Scans a file.
    fn scan_file(&mut self, path: PathBuf) -> PyResult<Py<ScanResults>> {
        Python::with_gil(|py| {
            scan_results_to_py(
                py,
                self.inner.scan_file(path).map_err(map_scan_err)?,
            )
        })
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
        Python::with_gil(|py| self.matching_rules.clone_ref(py))
    }

    #[getter]
    /// Rules that matched during the scan.
    fn module_outputs<'py>(&'py self, py: Python<'py>) -> &Bound<'py, PyDict> {
        self.module_outputs.bind(py)
    }
}

/// Represents a rule that matched while scanning some data.
#[pyclass]
struct Rule {
    identifier: String,
    namespace: String,
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

    /// A tuple of pairs `(identifier, value)` with the metadata associated to
    /// the rule.
    #[getter]
    fn metadata(&self) -> Py<PyTuple> {
        Python::with_gil(|py| self.metadata.clone_ref(py))
    }

    /// Patterns defined by the rule.
    #[getter]
    fn patterns(&self) -> Py<PyTuple> {
        Python::with_gil(|py| self.patterns.clone_ref(py))
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
        Python::with_gil(|py| self.matches.clone_ref(py))
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

#[pymethods]
impl Rules {
    /// Scans in-memory data with these rules.
    fn scan(&self, data: &[u8]) -> PyResult<Py<ScanResults>> {
        let mut scanner = yrx::Scanner::new(&self.inner.rules);
        Python::with_gil(|py| {
            scan_results_to_py(
                py,
                scanner
                    .scan(data)
                    .map_err(|err| ScanError::new_err(err.to_string()))?,
            )
        })
    }

    /// Serializes the rules into a file-like object.
    fn serialize_into(&self, file: PyObject) -> PyResult<()> {
        let f = PyFileLikeObject::with_requirements(
            file, false, true, false, false,
        )?;
        self.inner
            .rules
            .serialize_into(f)
            .map_err(|err| PyIOError::new_err(err.to_string()))
    }

    /// Deserializes rules from a file-like object.
    #[staticmethod]
    fn deserialize_from(file: PyObject) -> PyResult<Py<Rules>> {
        let f = PyFileLikeObject::with_requirements(
            file, true, false, false, false,
        )?;
        let rules = yrx::Rules::deserialize_from(f)
            .map_err(|err| PyIOError::new_err(err.to_string()))?;

        Python::with_gil(|py| Py::new(py, Rules::new(rules)))
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

    let module_outputs = PyDict::new_bound(py);
    let outputs = scan_results.module_outputs();

    // For better performance we only load the "json" module if there's
    // some module output.
    if outputs.len() > 0 {
        let json = PyModule::import_bound(py, "json")?;
        let json_loads = json.getattr("loads")?;
        for (module, output) in outputs {
            let module_output_json = proto_to_json(output).unwrap();
            let module_output =
                json_loads.call((module_output_json,), None)?;
            module_outputs.set_item(module, module_output)?;
        }
    }

    Py::new(
        py,
        ScanResults {
            matching_rules: PyTuple::new_bound(py, matching_rules).unbind(),
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
            metadata: PyTuple::new_bound(
                py,
                rule.metadata()
                    .map(|(ident, value)| metadata_to_py(py, ident, value)),
            )
            .unbind(),
            patterns: PyTuple::new_bound(
                py,
                rule.patterns()
                    .map(|pattern| pattern_to_py(py, pattern))
                    .collect::<Result<Vec<_>, _>>()?,
            )
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
        yrx::MetaValue::Integer(v) => v.to_object(py),
        yrx::MetaValue::Float(v) => v.to_object(py),
        yrx::MetaValue::Bool(v) => v.to_object(py),
        yrx::MetaValue::String(v) => v.to_object(py),
        yrx::MetaValue::Bytes(v) => v.to_object(py),
    };

    PyTuple::new_bound(py, [ident.to_object(py), value]).unbind()
}

fn pattern_to_py(py: Python, pattern: yrx::Pattern) -> PyResult<Py<Pattern>> {
    Py::new(
        py,
        Pattern {
            identifier: pattern.identifier().to_string(),
            matches: PyTuple::new_bound(
                py,
                pattern
                    .matches()
                    .map(|match_| match_to_py(py, match_))
                    .collect::<Result<Vec<_>, _>>()?,
            )
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
    m.add("CompileError", m.py().get_type_bound::<CompileError>())?;
    m.add("TimeoutError", m.py().get_type_bound::<TimeoutError>())?;
    m.add("ScanError", m.py().get_type_bound::<ScanError>())?;
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_class::<Rules>()?;
    m.add_class::<Scanner>()?;
    m.add_class::<Compiler>()?;
    m.add_class::<Rule>()?;
    m.add_class::<Pattern>()?;
    m.add_class::<Match>()?;
    Ok(())
}
