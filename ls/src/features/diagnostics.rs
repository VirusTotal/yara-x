use async_lsp::lsp_types::{Diagnostic, Range};

#[cfg(feature = "full-compiler")]
use async_lsp::lsp_types::{DiagnosticSeverity, NumberOrString};

use serde::{Deserialize, Serialize};

#[cfg(feature = "full-compiler")]
use crate::utils::position::span_to_range;

#[cfg(feature = "full-compiler")]
use yara_x::Compiler;

#[derive(Serialize, Deserialize)]
pub struct DiagnosticData {
    pub patches: Vec<Patch>,
}

#[derive(Serialize, Deserialize)]
pub struct Patch {
    pub range: Range,
    pub replacement: String,
}

/// Returns a diagnostic vector for the given source code.
#[allow(unused_variables)]
pub fn diagnostics(src: &str) -> Vec<Diagnostic> {
    #[allow(unused_mut)]
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    #[cfg(feature = "full-compiler")]
    diagnostics.extend(compiler_diagnostics(src));

    diagnostics
}

/// Return diagnostic vector for the given source code.
///
/// This function compiles the source code using the full YARA-X compiler
/// and collects all errors and warnings as LSP diagnostics. This provides
/// comprehensive feedback including type checking, semantic analysis,
/// and pattern validation - not just syntax errors.
#[cfg(feature = "full-compiler")]
pub fn compiler_diagnostics(src: &str) -> Vec<Diagnostic> {
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut compiler = Compiler::new();

    // Attempt to compile the source. We don't care about the result
    // since we want to collect all errors and warnings regardless.
    let _ = compiler.add_source(src);

    // Collect compiler errors
    for error in compiler.errors() {
        // Get the first label's span for the diagnostic location
        if let Some(label) = error.labels().next() {
            let patches = error
                .patches()
                .map(|patch| Patch {
                    range: span_to_range(patch.span().clone(), src),
                    replacement: patch.replacement().to_string(),
                })
                .collect();

            diagnostics.push(Diagnostic {
                range: span_to_range(label.span().clone(), src),
                message: error.title().to_string(),
                severity: Some(DiagnosticSeverity::ERROR),
                code: Some(NumberOrString::String(error.code().to_string())),
                data: Some(
                    serde_json::to_value(DiagnosticData { patches }).unwrap(),
                ),
                ..Default::default()
            });
        }
    }

    // Collect compiler warnings
    for warning in compiler.warnings() {
        // Get the first label's span for the diagnostic location
        if let Some(label) = warning.labels().next() {
            let patches = warning
                .patches()
                .map(|patch| Patch {
                    range: span_to_range(patch.span().clone(), src),
                    replacement: patch.replacement().to_string(),
                })
                .collect();

            diagnostics.push(Diagnostic {
                range: span_to_range(label.span().clone(), src),
                message: warning.title().to_string(),
                severity: Some(DiagnosticSeverity::WARNING),
                code: Some(NumberOrString::String(warning.code().to_string())),
                data: Some(
                    serde_json::to_value(DiagnosticData { patches }).unwrap(),
                ),
                ..Default::default()
            });
        }
    }

    diagnostics
}
