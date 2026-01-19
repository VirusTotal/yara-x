use async_lsp::lsp_types::{DocumentSymbol, SymbolKind};
use yara_x_parser::ast::{Item, WithSpan, AST};

use crate::document::Document;

pub fn document_symbol(document: &Document, ast: AST) -> Vec<DocumentSymbol> {
    let line_index = &document.line_index;
    let mut symbols = Vec::new();
    for item in ast.items {
        match item {
            Item::Import(import) => {
                let range = line_index.span_to_range(import.span());
                let module_name = import.module_name.to_string();
                if !module_name.is_empty() {
                    #[allow(deprecated)]
                    symbols.push(DocumentSymbol {
                        name: module_name,
                        detail: Some(String::from("import")),
                        kind: SymbolKind::MODULE,
                        tags: None,
                        deprecated: None,
                        range,
                        selection_range: range,
                        children: None,
                    })
                }
            }
            Item::Include(include) => {
                let range = line_index.span_to_range(include.span());
                let file_name = include.file_name.to_string();
                if !file_name.is_empty() {
                    #[allow(deprecated)]
                    symbols.push(DocumentSymbol {
                        name: file_name,
                        detail: Some(String::from("include")),
                        kind: SymbolKind::FILE,
                        tags: None,
                        deprecated: None,
                        range,
                        selection_range: range,
                        children: None,
                    });
                }
            }
            Item::Rule(rule) => {
                let mut children = Vec::new();

                if let Some(meta) = rule.meta {
                    children.extend(meta.iter().map(|meta| {
                        let range = line_index.span_to_range(meta.span());
                        #[allow(deprecated)]
                        DocumentSymbol {
                            name: meta.identifier.name.to_string(),
                            detail: None,
                            kind: SymbolKind::CONSTANT,
                            tags: None,
                            deprecated: None,
                            range,
                            selection_range: range,
                            children: None,
                        }
                    }))
                }

                if let Some(patterns) = rule.patterns {
                    children.extend(patterns.iter().map(|pattern| {
                        let range = line_index.span_to_range(pattern.span());
                        #[allow(deprecated)]
                        DocumentSymbol {
                            name: pattern.identifier().name.to_string(),
                            detail: None,
                            kind: SymbolKind::STRING,
                            tags: None,
                            deprecated: None,
                            range,
                            selection_range: range,
                            children: None,
                        }
                    }))
                }

                let range = line_index.span_to_range(rule.condition.span());
                #[allow(deprecated)]
                children.push(DocumentSymbol {
                    name: String::from("condition"),
                    detail: None,
                    kind: SymbolKind::BOOLEAN,
                    tags: None,
                    deprecated: None,
                    range,
                    selection_range: range,
                    children: None,
                });

                let range = line_index.span_to_range(rule.identifier.span());
                #[allow(deprecated)]
                symbols.push(DocumentSymbol {
                    name: rule.identifier.name.to_string(),
                    detail: Some(String::from("rule")),
                    kind: SymbolKind::FUNCTION,
                    tags: None,
                    deprecated: None,
                    selection_range: range,
                    range,
                    children: Some(children),
                });
            }
        }
    }

    symbols
}
