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
use std::marker::PhantomPinned;
use std::ops::Deref;
use std::pin::Pin;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyTuple;

use ::yara_x as yrx;

struct CompileError(yrx::Error);

impl From<CompileError> for PyErr {
    fn from(error: CompileError) -> Self {
        PyValueError::new_err(error.0.to_string())
    }
}

impl From<yrx::Error> for CompileError {
    fn from(other: yrx::Error) -> Self {
        Self(other)
    }
}

#[pyfunction]
fn compile(src: &str) -> Result<Rules, CompileError> {
    Ok(Rules {
        inner: Box::pin(PinnedRules {
            rules: yrx::compile(src)?,
            _pinned: PhantomPinned,
        }),
    })
}

/// Compiles YARA source code producing a set of compiled [`Rules`].
#[pyclass(unsendable)]
struct Compiler {
    inner: Option<yrx::Compiler<'static>>,
}

#[pymethods]
impl Compiler {
    /// Creates a new [`Compiler`].
    #[new]
    fn new() -> Self {
        Self { inner: Some(yrx::Compiler::new()) }
    }

    /// Adds a YARA source code to be compiled.
    ///
    /// This function can be used multiple times before calling [`Compiler::build`].
    fn add_source(&mut self, src: &str) -> Result<(), CompileError> {
        let compiler = self.inner.take().unwrap_or_else(yrx::Compiler::new);
        self.inner = Some(compiler.add_source(src)?);
        Ok(())
    }

    /// Creates a new namespace.
    ///
    /// Further calls to [`Compiler::add_source`] will put the rules under the
    /// newly created namespace.
    fn new_namespace(&mut self, namespace: &str) {
        let compiler = self.inner.take().unwrap_or_else(yrx::Compiler::new);
        self.inner = Some(compiler.new_namespace(namespace));
    }

    /// Builds the source code previously added to the compiler.
    ///
    /// This function returns an instance of [`Rules`] containing all the rules
    /// previously added with [`Compiler::add_source`] and sets the compiler
    /// to its initial empty state. The compiler can be re-used by adding more
    /// rules and calling this function again.
    fn build(&mut self) -> Rules {
        let compiler = self.inner.take().unwrap_or_else(yrx::Compiler::new);
        Rules {
            inner: Box::pin(PinnedRules {
                rules: compiler.build(),
                _pinned: PhantomPinned,
            }),
        }
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

    /// Scans in-memory data.
    #[pyo3(signature = (data))]
    fn scan(&mut self, data: &[u8]) -> Py<PyTuple> {
        let matches: Vec<String> = self
            .inner
            .scan(data)
            .matching_rules()
            .map(|rule| rule.name().to_string())
            .collect();

        Python::with_gil(|py| PyTuple::new(py, matches).into())
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

#[pymethods]
impl Rules {
    /// Scans in-memory data with these rules.
    #[pyo3(signature = (data))]
    fn scan(&self, data: &[u8]) -> Py<PyTuple> {
        let matches: Vec<String> = yrx::Scanner::new(&self.inner.rules)
            .scan(data)
            .matching_rules()
            .map(|rule| rule.name().to_string())
            .collect();

        Python::with_gil(|py| PyTuple::new(py, matches).into())
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
fn yara_x(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_class::<Rules>()?;
    m.add_class::<Scanner>()?;
    m.add_class::<Compiler>()?;
    Ok(())
}
