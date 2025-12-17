use async_lsp::lsp_types::{DocumentSymbol, SymbolKind};

use yara_x_parser::cst::{
    Immutable, Node, NodeOrToken, Nodes, SyntaxKind, CST,
};

use crate::utils::position::{node_to_range, token_to_range};

/// Returns document symbol response for the given document based on its CST.
#[allow(deprecated)]
pub fn document_symbol(cst: &CST) -> Vec<DocumentSymbol> {
    let mut all_symbols: Vec<DocumentSymbol> = Vec::new();

    for node in cst.root().children() {
        match node.kind() {
            // Import statement in the root of the document symbols
            SyntaxKind::IMPORT_STMT => {
                if let Some(NodeOrToken::Token(import_string)) =
                    node.children_with_tokens().find(|node_or_token| {
                        node_or_token.kind() == SyntaxKind::STRING_LIT
                    })
                {
                    let range = token_to_range(&import_string).unwrap();

                    all_symbols.push(DocumentSymbol {
                        name: String::from(import_string.text()),
                        detail: Some(String::from("Import statement")),
                        kind: SymbolKind::FILE,
                        tags: None,
                        deprecated: None,
                        range,
                        selection_range: range,
                        children: None,
                    });
                }
            }
            //Include statement in the root of the document symbols
            SyntaxKind::INCLUDE_STMT => {
                if let Some(NodeOrToken::Token(include_string)) =
                    node.children_with_tokens().find(|node_or_token| {
                        node_or_token.kind() == SyntaxKind::STRING_LIT
                    })
                {
                    let range = token_to_range(&include_string).unwrap();

                    all_symbols.push(DocumentSymbol {
                        name: String::from(include_string.text()),
                        detail: Some(String::from("Include statement")),
                        kind: SymbolKind::FILE,
                        tags: None,
                        deprecated: None,
                        range,
                        selection_range: range,
                        children: None,
                    });
                }
            }
            //Rule definition in the root of the document symbols
            SyntaxKind::RULE_DECL => {
                if let Some(NodeOrToken::Token(rule_ident)) =
                    node.children_with_tokens().find(|node_or_token| {
                        node_or_token.kind() == SyntaxKind::IDENT
                    })
                {
                    //Extract all rule blocks as children for the rule definition symbol
                    let mut rule_symbols: Vec<DocumentSymbol> = Vec::new();

                    for block in node.children() {
                        match block.kind() {
                            SyntaxKind::META_BLK => {
                                let mut meta_blk_symbol =
                                    block_document_symbol(&block, "meta");

                                meta_blk_symbol.children = collect_definition(
                                    block.children(),
                                    "Meta attribute",
                                    SymbolKind::ENUM_MEMBER,
                                );

                                rule_symbols.push(meta_blk_symbol);
                            }
                            SyntaxKind::PATTERNS_BLK => {
                                let mut pattern_blk_symbol =
                                    block_document_symbol(&block, "strings");

                                pattern_blk_symbol.children =
                                    collect_definition(
                                        block.children(),
                                        "Pattern definition",
                                        SymbolKind::VARIABLE,
                                    );

                                rule_symbols.push(pattern_blk_symbol);
                            }
                            SyntaxKind::CONDITION_BLK => {
                                rule_symbols.push(block_document_symbol(
                                    &block,
                                    "condition",
                                ));
                            }
                            _ => {}
                        }
                    }

                    //Add these block symbols as children for rule definition symbol
                    let range = node_to_range(&node).unwrap();

                    all_symbols.push(DocumentSymbol {
                        name: String::from(rule_ident.text()),
                        detail: Some(String::from("Rule definition")),
                        kind: SymbolKind::FUNCTION,
                        tags: None,
                        deprecated: None,
                        range,
                        selection_range: range,
                        children: Some(rule_symbols),
                    });
                }
            }
            _ => {}
        }
    }

    all_symbols
}

/// Returns document symbol for certain block within a rule.
#[allow(deprecated)]
fn block_document_symbol(
    block: &Node<Immutable>,
    name: &str,
) -> DocumentSymbol {
    let range = node_to_range(block).unwrap();

    DocumentSymbol {
        name: String::from(name),
        detail: None,
        kind: SymbolKind::PROPERTY,
        tags: None,
        deprecated: None,
        range,
        selection_range: range,
        children: None,
    }
}

/// Returns vector of documents symbols collected from the given children
/// nodes. Used for collecting meta attributes or pattern declarations
/// as document symbols.
#[allow(deprecated)]
fn collect_definition(
    children: Nodes<Immutable>,
    detail: &str,
    kind: SymbolKind,
) -> Option<Vec<DocumentSymbol>> {
    let mut definitions: Vec<DocumentSymbol> = Vec::new();

    for definition in children {
        let range = node_to_range(&definition).unwrap();
        let name = String::from(definition.first_token()?.text());

        definitions.push(DocumentSymbol {
            name,
            detail: Some(String::from(detail)),
            kind,
            tags: None,
            deprecated: None,
            range,
            selection_range: range,
            children: None,
        });
    }

    Some(definitions)
}
