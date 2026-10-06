use std::sync::Arc;

use async_lsp::lsp_types::{
    HoverContents, MarkupContent, MarkupKind, Position, Url,
};
use itertools::Itertools;
use yara_x::mods::reflect::Type;
use yara_x_parser::cst::{NodeOrToken, SyntaxKind, Utf8};

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::{
    find_declaration, prev_non_trivia_token, token_at_position,
};

use crate::utils::modules::{get_type, ty_to_string};
use crate::utils::rule_documentation::RuleDocumentationBuilder;

pub fn hover(
    documents: Arc<DocumentStorage>,
    uri: Url,
    pos: Position,
) -> Option<HoverContents> {
    let document = documents.get(&uri)?;

    // Find the token at the position where the user is hovering.
    let token = token_at_position(&document.cst, pos)?;

    match token.kind() {
        // Pattern identifiers in any of their forms (i.e: $a, #a, @a, !a).
        // Notice that identifiers like $, #, @ and ! are ignored, as they
        // don't represent a single pattern.
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH
            if token.len::<Utf8>() >= 2 =>
        {
            RuleDocumentationBuilder::from_token(&token)
                .and_then(|builder| builder.pattern_markdown(token.text()))
                .map(HoverContents::Markup)
        }
        // Other identifiers.
        SyntaxKind::IDENT => {
            let structure = prev_non_trivia_token(&token)
                .filter(|token| token.kind() == SyntaxKind::DOT)
                .and_then(|token| prev_non_trivia_token(&token))
                .and_then(|token| get_type(&token))
                .and_then(|ty| {
                    if let Type::Struct(s) = ty { Some(s) } else { None }
                });

            let field = structure
                .as_ref()
                .and_then(|s| s.fields().find(|f| f.name() == token.text()));

            if let Some(field) = field {
                match field.ty() {
                    Type::Func(func) => {
                        let documentation = func
                                .signatures
                                .iter()
                                .filter_map(|signature| {
                                    signature.doc().map(|doc| {
                                        format!(
                                            "### `{}({}) -> {}`\n\n***\n\n{}\n\n***\n\n",
                                            token.text(),
                                            signature
                                                .args()
                                                .map(|(arg_name, arg_ty)| format!(
                                                    "{}: {}",
                                                    arg_name,
                                                    ty_to_string(arg_ty)
                                                ))
                                                .join(", "),
                                            ty_to_string(signature.ret_type()),
                                            doc
                                        )
                                    })
                                })
                                .join("\n");

                        if !documentation.is_empty() {
                            return Some(HoverContents::Markup(
                                MarkupContent {
                                    kind: MarkupKind::Markdown,
                                    value: documentation,
                                },
                            ));
                        }
                    }
                    ty => {
                        let mut value = format!(
                            "### `{}: {}`",
                            token.text(),
                            ty_to_string(&ty)
                        );
                        if let Some(d) = field.doc() {
                            value
                                .push_str(&format!("\n\n***\n\n{}\n\n***", d));
                        }
                        return Some(HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value,
                        }));
                    }
                }
            }

            if let Some((_, n)) = find_declaration(&token) {
                let text = n
                    .children_with_tokens()
                    .take_while(|node_or_token| {
                        node_or_token.kind() != SyntaxKind::COLON
                    })
                    .fold(String::new(), |mut acc, node_or_token| {
                        match node_or_token {
                            NodeOrToken::Token(t) => acc.push_str(t.text()),
                            NodeOrToken::Node(n) => n
                                .text()
                                .for_each_chunks(|chunk| acc.push_str(chunk)),
                        }
                        acc
                    });

                return Some(HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: format!("Declared:\n\n```\n{text}\n```"),
                }));
            }

            let (rule, _) = documents.find_rule_definition(&uri, &token)?;

            let builder = RuleDocumentationBuilder::new(rule);

            Some(HoverContents::Markup(builder.rule_markdown()))
        }
        _ => None,
    }
}
