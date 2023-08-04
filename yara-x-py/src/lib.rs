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
use std::mem;
use std::ops::Deref;
use std::pin::Pin;
use std::time::Duration;

use pyo3::exceptions::PyException;
use pyo3::exceptions::{PySyntaxError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyFloat, PyInt, PyString, PyTuple};

use ::yara_x as yrx;

#[pyfunction]
fn compile(src: &str) -> PyResult<Rules> {
    Ok(Rules {
        inner: Box::pin(PinnedRules {
            rules: yrx::compile(src)
                .map_err(|err| PyValueError::new_err(err.to_string()))?,
            _pinned: PhantomPinned,
        }),
    })
}

/// Compiles YARA source code producing a set of compiled [`Rules`].
#[pyclass(unsendable)]
struct Compiler {
    inner: yrx::Compiler<'static>,
}

#[pymethods]
impl Compiler {
    /// Creates a new [`Compiler`].
    #[new]
    fn new() -> Self {
        Self { inner: yrx::Compiler::new() }
    }

    /// Adds a YARA source code to be compiled.
    ///
    /// This function can be used multiple times before calling [`Compiler::build`].
    fn add_source(&mut self, src: &str) -> PyResult<()> {
        self.inner
            .add_source(src)
            .map_err(|err| PySyntaxError::new_err(err.to_string()))?;
        Ok(())
    }

    /// Defines a global variable and sets its initial value.
    ///
    /// Global variables must be defined before calling [`Compiler::add_source`]
    /// with some YARA rule that uses the variable. The variable will retain its
    /// initial value when the [`Rules`] are used for scanning data, however
    /// each scanner can change the variable's value by calling
    /// [`crate::Scanner::set_global`].
    fn define_global(&mut self, ident: &str, value: &PyAny) -> PyResult<()> {
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

    /// Builds the source code previously added to the compiler.
    ///
    /// This function returns an instance of [`Rules`] containing all the rules
    /// previously added with [`Compiler::add_source`] and sets the compiler
    /// to its initial empty state.
    fn build(&mut self) -> Rules {
        let compiler = mem::replace(&mut self.inner, yrx::Compiler::new());
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

    /// Sets the value of a global variable.
    ///
    /// The variable must has been previously defined by calling
    /// [`Compiler::define_global`], and the type it has during the definition
    /// must match the type of the new value.
    ///
    /// The variable will retain the new value in subsequent scans, unless this
    /// function is called again for setting a new value.
    fn set_global(&mut self, ident: &str, value: &PyAny) -> PyResult<()> {
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

    /// Scans in-memory data.
    #[pyo3(signature = (data))]
    fn scan(&mut self, data: &[u8]) -> PyResult<Py<PyTuple>> {
        let matches: Vec<String> = self
            .inner
            .scan(data)
            .map_err(|err| PyException::new_err(err.to_string()))?
            .matching_rules()
            .map(|rule| rule.name().to_string())
            .collect();

        Ok(Python::with_gil(|py| PyTuple::new(py, matches).into()))
    }
}

#[pyclass]
struct MatchingRule {
    name: String,
    namespace: String,
}

#[pymethods]
impl MatchingRule {
    #[getter]
    fn name(&self) -> &str {
        self.name.as_str()
    }

    #[getter]
    fn namespace(&self) -> &str {
        self.namespace.as_str()
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
    fn scan(&self, data: &[u8]) -> PyResult<Py<PyTuple>> {
        let mut scanner = yrx::Scanner::new(&self.inner.rules);
        let scan_results = scanner
            .scan(data)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let matches = scan_results.matching_rules();

        Ok(Python::with_gil(|py| {
            PyTuple::new(
                py,
                matches.map(|rule| {
                    MatchingRule {
                        name: rule.name().to_string(),
                        namespace: rule.namespace().to_string(),
                    }
                    .into_py(py)
                }),
            )
            .into()
        }))
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
    m.add_class::<MatchingRule>()?;
    Ok(())
}
