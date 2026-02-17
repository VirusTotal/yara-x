use std::sync::Arc;

use async_lsp::lsp_types::{
    HoverContents, MarkupContent, MarkupKind, Position, Url,
};

use yara_x_parser::cst::{Immutable, Node, NodeOrToken, SyntaxKind, Utf8};

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::{
    find_identifier_declaration, pattern_from_ident, rule_containing_token,
    token_at_position,
};

/// Builder for hover Markdown representation of a rule.
struct RuleHoverBuilder {
    name: String,
    metas: Option<Node<Immutable>>,
    patterns: Option<Node<Immutable>>,
    condition: Option<Node<Immutable>>,
}

impl RuleHoverBuilder {
    /// Creates a new RuleHoverBuilder with the given rule identifier.
    pub fn new(name: &str) -> Self {
        RuleHoverBuilder {
            name: String::from(name),
            metas: None,
            patterns: None,
            condition: None,
        }
    }

    /// Creates the Markdown representation of the rule.
    /// It includes the rule name, metas, strings, and condition.
    pub fn get_markdown(&self) -> String {
        let mut markdown = format!("### rule `{}`\n", self.name);

        if let Some(metas) = &self.process_metas() {
            markdown.push_str("```\n");
            markdown.push_str(metas);
            markdown.push_str("\n```\n");
        }

        markdown
    }

    /// Processes the meta block and returns its markdown representation.
    fn process_metas(&self) -> Option<String> {
        Some(
            self.metas
                .as_ref()?
                // All children in METAS_BLK should be META_DEF.
                .children()
                .map(|node| format!("{}\n", node.text()))
                .collect(),
        )
    }

    /// Sets the meta block of the rule.
    pub fn set_metas(&mut self, meta: Node<Immutable>) {
        self.metas = Some(meta);
    }

    /// Sets the strings block of the rule.
    pub fn set_patterns(&mut self, strings: Node<Immutable>) {
        self.patterns = Some(strings);
    }

    /// Sets the condition block of the rule.
    pub fn set_condition(&mut self, condition: Node<Immutable>) {
        self.condition = Some(condition);
    }
}

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
            let rule = rule_containing_token(&token)?;
            let pattern = pattern_from_ident(&rule, token.text())?;

            Some(HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: format!("Pattern value is:\n\n`{}`", pattern.text()),
            }))
        }
        // Rule identifiers.
        SyntaxKind::IDENT => {
            if let Some((_, n)) = find_identifier_declaration(&token) {
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

            let (rule, _) =
                documents.find_rule_definition(&uri, token.text())?;

            let mut builder = RuleHoverBuilder::new(token.text());

            for child in rule.children() {
                match child.kind() {
                    SyntaxKind::META_BLK => {
                        builder.set_metas(child);
                    }
                    SyntaxKind::PATTERNS_BLK => {
                        builder.set_patterns(child);
                    }
                    SyntaxKind::CONDITION_BLK => {
                        builder.set_condition(child);
                    }
                    _ => {}
                }
            }

            Some(HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: builder.get_markdown(),
            }))
        }
        _ => None,
    }
}
