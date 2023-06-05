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

#[pyclass(unsendable)]
struct Compiler {
    inner: Option<yrx::Compiler<'static>>,
}

#[pymethods]
impl Compiler {
    #[new]
    fn new() -> Self {
        Self { inner: Some(yrx::Compiler::new()) }
    }

    fn add_source(&mut self, src: &str) -> Result<(), CompileError> {
        let compiler = self.inner.take().unwrap_or_else(yrx::Compiler::new);
        self.inner = Some(compiler.add_source(src)?);
        Ok(())
    }

    fn new_namespace(&mut self, namespace: &str) {
        let compiler = self.inner.take().unwrap_or_else(yrx::Compiler::new);
        self.inner = Some(compiler.new_namespace(namespace));
    }

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

#[pyclass(unsendable)]
struct Scanner {
    _rules: Py<Rules>,
    inner: yrx::Scanner<'static>,
}

#[pymethods]
impl Scanner {
    #[new]
    fn new(rules: Py<Rules>) -> Self {
        Python::with_gil(|py| {
            let rr: &'static yrx::Rules = {
                let r = rules.borrow(py);
                let p: *const yrx::Rules = &r.deref().inner.rules;
                unsafe { &*p }
            };
            Self { _rules: rules, inner: yrx::Scanner::new(rr) }
        })
    }

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

#[pymodule]
fn yara_x(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_class::<Rules>()?;
    m.add_class::<Scanner>()?;
    m.add_class::<Compiler>()?;
    Ok(())
}
