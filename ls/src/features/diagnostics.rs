use std::sync::Arc;

use async_lsp::lsp_types::{
    Diagnostic, DiagnosticRelatedInformation, Location, Range, Url,
};
#[cfg(feature = "full-compiler")]
use async_lsp::lsp_types::{DiagnosticSeverity, NumberOrString};
use dashmap::mapref::one::Ref;
use serde::{Deserialize, Serialize};

use crate::configuration::MetadataValidationRule;
use crate::documents::{document::Document, storage::DocumentStorage};

#[cfg(feature = "full-compiler")]
use yara_x::linters;
#[cfg(feature = "full-compiler")]
use yara_x::{Compiler, SourceCode};

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
pub fn diagnostics(
    documents: Arc<DocumentStorage>,
    uri: Url,
    metadata_validation: &Vec<MetadataValidationRule>,
    rule_name_validation: &Option<String>,
) -> Vec<Diagnostic> {
    #[allow(unused_mut)]
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    let doc = documents.get(&uri);

    if let Some(doc) = doc {
        #[cfg(feature = "full-compiler")]
        diagnostics.extend(compiler_diagnostics(
            doc,
            metadata_validation,
            rule_name_validation,
        ));
    }

    diagnostics
}

/// Return diagnostic vector for the given source code.
///
/// This function compiles the source code using the full YARA-X 'compiler'
/// and collects all errors and warnings as LSP diagnostics. This provides
/// comprehensive feedback including type checking, semantic analysis,
/// and pattern validation - not just syntax errors.
#[cfg(feature = "full-compiler")]
pub fn compiler_diagnostics(
    document: Ref<'_, Url, Document>,
    metadata_validation: &Vec<MetadataValidationRule>,
    rule_name_validation: &Option<String>,
) -> Vec<Diagnostic> {
    let source_code = SourceCode::from(document.text.as_str())
        .with_origin(document.uri.clone());

    let mut compiler = Compiler::new();

    if let Some(regex) = rule_name_validation {
        if let Ok(linter) = linters::rule_name(regex) {
            compiler.add_linter(linter);
        }
    }

    for validation_rule in metadata_validation {
        let mut linter = linters::metadata(&validation_rule.identifier)
            .required(validation_rule.required);

        if let Some(ty) = &validation_rule.ty {
            let predicate = match ty.as_str() {
                "string" => |meta: &yara_x_parser::ast::Meta| {
                    matches!(
                        meta.value,
                        yara_x_parser::ast::MetaValue::String(_)
                    )
                },
                "integer" => |meta: &yara_x_parser::ast::Meta| {
                    matches!(
                        meta.value,
                        yara_x_parser::ast::MetaValue::Integer(_)
                    )
                },
                "float" => |meta: &yara_x_parser::ast::Meta| {
                    matches!(
                        meta.value,
                        yara_x_parser::ast::MetaValue::Float(_)
                    )
                },
                "bool" => |meta: &yara_x_parser::ast::Meta| {
                    matches!(
                        meta.value,
                        yara_x_parser::ast::MetaValue::Bool(_)
                    )
                },
                _ => continue,
            };
            linter = linter.validator(
                predicate,
                format!("`{}` must be a `{}`", validation_rule.identifier, ty),
            );
        }

        compiler.add_linter(linter);
    }

    // VSCode don't handle well error messages with too many columns.
    compiler.errors_max_width(110);
    // Attempt to compile the source. We don't care about the result
    // since we want to collect all errors and warnings regardless.
    let _ = compiler.add_source(source_code);

    let line_index = &document.line_index;
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    // Collect compiler errors
    for error in compiler.errors() {
        // Only take into account the labels for the current document.
        let labels = error.labels().filter(|label| {
            label
                .origin()
                .is_some_and(|origin| origin == document.uri.as_str())
        });

        for label in labels {
            let range = line_index.span_to_range(label.span().clone());
            let patches = error
                .patches()
                .map(|patch| Patch {
                    range: line_index.span_to_range(patch.span()),
                    replacement: patch.replacement().to_string(),
                })
                .collect();

            diagnostics.push(Diagnostic {
                range,
                message: error.title().to_string(),
                severity: Some(DiagnosticSeverity::ERROR),
                code: Some(NumberOrString::String(error.code().to_string())),
                related_information: Some(vec![
                    DiagnosticRelatedInformation {
                        location: Location {
                            range,
                            uri: document.uri.clone(),
                        },
                        message: label.text().to_string(),
                    },
                ]),
                data: Some(
                    serde_json::to_value(DiagnosticData { patches }).unwrap(),
                ),
                ..Default::default()
            });
        }
    }

    // Collect compiler warnings
    for warning in compiler.warnings() {
        // Only take into account the labels for the current document.
        let labels = warning.labels().filter(|label| {
            label
                .origin()
                .is_some_and(|origin| origin == document.uri.as_str())
        });

        // Get the first label's span for the diagnostic location
        for label in labels {
            let range = line_index.span_to_range(label.span().clone());
            let patches = warning
                .patches()
                .map(|patch| Patch {
                    range,
                    replacement: patch.replacement().to_string(),
                })
                .collect();

            diagnostics.push(Diagnostic {
                range,
                message: warning.title().to_string(),
                severity: Some(DiagnosticSeverity::WARNING),
                code: Some(NumberOrString::String(warning.code().to_string())),
                related_information: Some(vec![
                    DiagnosticRelatedInformation {
                        location: Location {
                            range,
                            uri: document.uri.clone(),
                        },
                        message: label.text().to_string(),
                    },
                ]),
                data: Some(
                    serde_json::to_value(DiagnosticData { patches }).unwrap(),
                ),
                ..Default::default()
            });
        }
    }

    diagnostics
}
