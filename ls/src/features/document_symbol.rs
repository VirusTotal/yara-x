use crate::utils::position::span_to_range;
use async_lsp::lsp_types::{DocumentSymbol, SymbolKind};
use yara_x_parser::ast::{Item, WithSpan, AST};

pub fn document_symbol(src: &str, ast: AST) -> Vec<DocumentSymbol> {
    let mut symbols = Vec::new();
    for item in ast.items {
        match item {
            Item::Import(import) => {
                let range = span_to_range(import.span(), src);
                #[allow(deprecated)]
                symbols.push(DocumentSymbol {
                    name: import.module_name.to_string(),
                    detail: Some(String::from("import")),
                    kind: SymbolKind::MODULE,
                    tags: None,
                    deprecated: None,
                    range,
                    selection_range: range,
                    children: None,
                })
            }
            Item::Include(include) => {
                let range = span_to_range(include.span(), src);
                #[allow(deprecated)]
                symbols.push(DocumentSymbol {
                    name: String::from(include.file_name),
                    detail: Some(String::from("include")),
                    kind: SymbolKind::FILE,
                    tags: None,
                    deprecated: None,
                    range,
                    selection_range: range,
                    children: None,
                });
            }
            Item::Rule(rule) => {
                let mut children = Vec::new();

                if let Some(meta) = rule.meta {
                    children.extend(meta.iter().map(|meta| {
                        let range = span_to_range(meta.span(), src);
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
                        let range = span_to_range(pattern.span(), src);
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

                let range = span_to_range(rule.condition.span(), src);
                #[allow(deprecated)]
                children.push(DocumentSymbol {
                    name: "condition".to_string(),
                    detail: None,
                    kind: SymbolKind::BOOLEAN,
                    tags: None,
                    deprecated: None,
                    range,
                    selection_range: range,
                    children: None,
                });

                let range = span_to_range(rule.identifier.span(), src);
                #[allow(deprecated)]
                symbols.push(DocumentSymbol {
                    name: String::from(rule.identifier.name),
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
