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
        diagnostics.extend(compiler_diagnostics(
            doc,
            documents.workspace(),
            config,
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
pub fn compiler_diagnostics(
    document: Ref<'_, Url, Document>,
    #[allow(unused_variables)] workspace: Option<&Url>,
    config: Arc<Config>,
) -> Vec<Diagnostic> {
    let source_code = SourceCode::from(document.text.as_str())
        .with_origin(document.uri.clone());

    let mut compiler = Compiler::new();

    // The folder where the document is located and the workspace folder (if
    // available) are added as include directories in order to support
    // relative include paths.
    //
    // .to_file_path() is not present in WASM targets that lack
    // file-system support.
    #[cfg(any(unix, windows, target_os = "wasi"))]
    {
        if let Ok(file_path) = document.uri.to_file_path()
            && let Some(folder_path) = file_path.parent()
        {
            compiler.add_include_dir(folder_path);
        }

        if let Some(workspace_uri) = workspace
            && let Ok(workspace_path) = workspace_uri.to_file_path()
        {
            compiler.add_include_dir(workspace_path);
        }
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
                    // Pre-compile the regex outside the validator closure:
                    // `initialization_options` and `load_config` may store an
                    // invalid regex in `Config`, and calling `.unwrap()` inside
                    // the validator would panic when linting a matching rule.
                    if let Some(pattern) = &validation_rule.regex
                        && let Ok(re) = Regex::new(pattern)
                    {
                        compiler.add_linter(linter.validator(
                            move |meta| {
                                if let yara_x_parser::ast::MetaValue::String(
                                    value,
                                ) = &meta.value
                                {
                                    re.is_match(value.0)
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
                                yara_x_parser::ast::MetaValue::Bool(_)
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
                _ => {
                    compiler.add_linter(linter);
                }
            };
        } else {
            compiler.add_linter(linter);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::MetadataValidationRule;

    #[test]
    fn test_diagnostics_invalid_metadata_regex() {
        let storage = Arc::new(DocumentStorage::new());
        let uri = Url::parse("file:///test.yar").unwrap();
        storage.insert(
            uri.clone(),
            r#"rule r {
              meta:
                author = "Alice"
                ticket = 123
              condition:
                true
            }"#
            .to_string(),
        );

        let config = Arc::new(Config {
            metadata_validation: vec![
                MetadataValidationRule {
                    identifier: "author".to_string(),
                    required: true,
                    ty: Some("string".to_string()),
                    format: None,
                    regex: Some("[unclosed".to_string()),
                },
                MetadataValidationRule {
                    identifier: "ticket".to_string(),
                    required: false,
                    ty: Some("string".to_string()),
                    format: None,
                    regex: Some("[also-invalid".to_string()),
                },
                MetadataValidationRule {
                    identifier: "author".to_string(),
                    required: false,
                    ty: Some("string".to_string()),
                    format: None,
                    regex: Some("^Bob$".to_string()),
                },
            ],
            ..Default::default()
        });

        // Must not panic on invalid regexes, while still enforcing string type
        // on `ticket` and valid regexes on `author`.
        let diags = diagnostics(storage, uri, config);
        let invalid_meta_diags: Vec<_> = diags
            .iter()
            .filter(|d| {
                d.code
                    == Some(NumberOrString::String(
                        "invalid_metadata".to_string(),
                    ))
            })
            .collect();
        assert_eq!(invalid_meta_diags.len(), 2);
    }
}
