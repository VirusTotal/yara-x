use async_lsp::lsp_types::{
    Location, OneOf, SymbolKind, Url, WorkspaceLocation, WorkspaceSymbol,
    WorkspaceSymbolResponse,
};
use std::sync::Arc;
use yara_x_parser::cst::{Immutable, Node, SyntaxKind};

use crate::{
    documents::storage::DocumentStorage, utils::position::node_to_range,
};

/// Returns true, when the workspace symbol name matches the user query using
/// relaxed, case-insensitive matching. As stated in the protocol specification,
/// the language server should not do the prefix, substring or other strict matching.
fn relaxed_query_matching(name: &str, query: &str) -> bool {
    let mut name_chars = name.chars().flat_map(char::to_lowercase);

    query.chars().flat_map(char::to_lowercase).all(|query_char| {
        name_chars.by_ref().any(|name_char| name_char == query_char)
    })
}

pub fn workspace_symbol(
    documents: Arc<DocumentStorage>,
    workspace_resolve_location: bool,
    query: &str,
) -> Option<WorkspaceSymbolResponse> {
    // If client supports resolve operation for workspace symbols, then the language
    // server can compute the location of the symbols later. Otherwise, language server
    // has to compute the position right away here.
    let location = if workspace_resolve_location {
        |uri: Url, _node: Node<Immutable>| {
            OneOf::Right(WorkspaceLocation { uri })
        }
    } else {
        |uri: Url, node: Node<Immutable>| {
            OneOf::Left(Location { uri, range: node_to_range(&node).unwrap() })
        }
    };

    Some(WorkspaceSymbolResponse::Nested(
        documents
            .workspace_rules()?
            .filter_map(|(rule_decl, uri)| {
                if let Some(name) = rule_decl
                    .children_with_tokens()
                    .find_map(|ident| {
                        if ident.kind() == SyntaxKind::IDENT {
                            ident.into_token()
                        } else {
                            None
                        }
                    })
                    .map(|token| token.text().to_string())
                    && relaxed_query_matching(&name, query)
                {
                    Some(WorkspaceSymbol {
                        name,
                        // The same kind for rules as in Document Symbols feature
                        kind: SymbolKind::FUNCTION,
                        tags: None,
                        container_name: None,
                        location: location(uri, rule_decl),
                        data: None,
                    })
                } else {
                    None
                }
            })
            .collect(),
    ))
}

pub fn workspace_symbol_resolve(
    documents: Arc<DocumentStorage>,
    symbol: WorkspaceSymbol,
) -> WorkspaceSymbol {
    if let OneOf::Right(WorkspaceLocation { uri }) = &symbol.location
        && let Some(rule) = documents.workspace_resolve(uri, &symbol.name)
    {
        WorkspaceSymbol {
            location: OneOf::Left(Location {
                uri: uri.clone(),
                range: node_to_range(&rule).unwrap(),
            }),
            ..symbol
        }
    } else {
        symbol
    }
}
