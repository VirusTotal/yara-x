use std::sync::Arc;

use async_lsp::lsp_types::{Diagnostic, Range, Url};

use async_lsp::lsp_types::{
    DiagnosticRelatedInformation, DiagnosticSeverity, Location, NumberOrString,
};

use dashmap::mapref::one::Ref;
use serde::{Deserialize, Serialize};

use chrono::NaiveDate;
use regex::Regex;

use crate::configuration::Config;

use crate::documents::document::Document;
use crate::documents::storage::DocumentStorage;

use yara_x::linters;
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
    config: Arc<Config>,
) -> Vec<Diagnostic> {
    #[allow(unused_mut)]
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    let doc = documents.get(&uri);

    if let Some(doc) = doc {
        diagnostics.extend(compiler_diagnostics(doc, config));
    }

    diagnostics
}

/// Return diagnostic vector for the given source code.
///
/// This function compiles the source code using the full YARA-X 'compiler'
/// and collects all errors and warnings as LSP diagnostics. This provides
/// comprehensive feedback including type checking, semantic analysis,
/// and pattern validation - not just syntax errors.
pub fn compiler_diagnostics(
    document: Ref<'_, Url, Document>,
    config: Arc<Config>,
) -> Vec<Diagnostic> {
    let source_code = SourceCode::from(document.text.as_str())
        .with_origin(document.uri.clone());

    let mut compiler = Compiler::new();

    // The folder where the document is located is added as an include
    // directory in order to support relative include paths.
    if let Ok(file_path) = document.uri.to_file_path()
        && let Some(folder_path) = file_path.parent()
    {
        compiler.add_include_dir(folder_path);
    }

    // These features are required by the "vt" module. Some field will be
    // recognized only if these features are enabled.
    compiler
        .enable_feature("file")
        .enable_feature("url")
        .enable_feature("ip_address")
        .enable_feature("domain");

    if let Some(regex) = &config.rule_name_validation
        && let Ok(linter) = linters::rule_name(regex)
    {
        compiler.add_linter(linter);
    }

    for validation_rule in &config.metadata_validation {
        let linter = linters::metadata(&validation_rule.identifier)
            .required(validation_rule.required);

        if let Some(ty) = &validation_rule.ty {
            match ty.as_str() {
                "string" => {
                    if let Some(pattern) = &validation_rule.regex {
                        compiler.add_linter(linter.validator(
                            |meta| {
                                if let yara_x_parser::ast::MetaValue::String(
                                    value,
                                ) = &meta.value
                                {
                                    Regex::new(pattern).unwrap().is_match(value.0)
                                } else {
                                    false
                                }
                            },
                            format!(
                                "`{}` must be a string and match the pattern `{}`",
                                validation_rule.identifier, pattern
                            ),
                        ));
                    } else {
                        compiler.add_linter(linter.validator(
                            |meta| {
                                matches!(
                                    meta.value,
                                    yara_x_parser::ast::MetaValue::String(_)
                                )
                            },
                            format!(
                                "`{}` must be a `string`",
                                validation_rule.identifier
                            ),
                        ));
                    }
                }
                "integer" => {
                    compiler.add_linter(linter.validator(
                        |meta| {
                            matches!(
                                meta.value,
                                yara_x_parser::ast::MetaValue::Integer(_)
                            )
                        },
                        format!(
                            "`{}` must be a `integer`",
                            validation_rule.identifier
                        ),
                    ));
                }
                "float" => {
                    compiler.add_linter(linter.validator(
                        |meta| {
                            matches!(
                                meta.value,
                                yara_x_parser::ast::MetaValue::Float(_)
                            )
                        },
                        format!(
                            "`{}` must be a `float`",
                            validation_rule.identifier
                        ),
                    ));
                }
                "bool" => {
                    compiler.add_linter(linter.validator(
                        |meta| {
                            matches!(
                                meta.value,
                                yara_x_parser::ast::MetaValue::Float(_)
                            )
                        },
                        format!(
                            "`{}` must be a `bool`",
                            validation_rule.identifier
                        ),
                    ));
                }
                "date" => {
                    let format = validation_rule
                        .format
                        .as_deref()
                        .unwrap_or("%Y-%m-%d");

                    compiler.add_linter(linter.validator(
                        |meta| {
                            if let yara_x_parser::ast::MetaValue::String(
                                value,
                            ) = &meta.value
                            {
                                NaiveDate::parse_from_str(value.0, format)
                                    .is_ok()
                            } else {
                                false
                            }
                        },
                        format!(
                            "`{}` must be a `date` with format `{}`",
                            validation_rule.identifier, format
                        ),
                    ));
                }
                _ => {}
            };
        }
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
