use async_lsp::lsp_types::{MarkupContent, MarkupKind};
use itertools::Itertools;
use yara_x_parser::cst::{Immutable, Node, SyntaxKind, Token};

use crate::{
    configuration::DocumentationConfiguration,
    utils::cst_traversal::{
        pattern_from_string, rule_containing_token, rule_ident,
    },
};

macro_rules! code_block {
    ($code:expr) => {
        format!("```\n{}\n```\n", $code)
    };
    ($title:expr, $code:expr) => {
        format!("{}\n\n```\n{}\n```\n", $title, $code)
    };
}

/// Builder for the Markdown representation of a rule.
///
/// Only the rule's `RULE_DECL` node is stored; the Markdown fragments are
/// computed from it on demand.
pub(crate) struct RuleDocumentationBuilder {
    rule: Node<Immutable>,
}

impl RuleDocumentationBuilder {
    /// Creates a new builder for the given `RULE_DECL` node.
    pub(crate) fn new(rule: Node<Immutable>) -> Self {
        Self { rule }
    }

    /// Creates a new builder for the given token.
    ///
    /// Returns `None` if the token is not contained in some rule.
    pub(crate) fn from_token(token: &Token<Immutable>) -> Option<Self> {
        rule_containing_token(token).map(Self::new)
    }

    /// Creates the Markdown representation of the pattern identified as
    /// `name`.
    ///
    /// Returns `None` if the rule doesn't declare such pattern.
    pub fn pattern_single_markdown(
        &self,
        name: &str,
    ) -> Option<MarkupContent> {
        let pattern = pattern_from_string(&self.rule, name)?;

        Some(Self::pattern_node_markdown(&pattern))
    }

    #[inline]
    pub fn pattern_node_markdown(pattern: &Node<Immutable>) -> MarkupContent {
        MarkupContent {
            kind: MarkupKind::Markdown,
            value: code_block!("Pattern value is:", pattern.text()),
        }
    }

    /// Creates the Markdown representation of the rule.
    pub fn rule_markdown(
        &self,
        configuration: &DocumentationConfiguration,
    ) -> MarkupContent {
        let name = rule_ident(&self.rule)
            .map(|token| token.text().to_string())
            .unwrap_or_default();

        let mut markdown = format!("## rule `{name}`\n");

        if let Some(block) = self.meta_block_markdown() {
            markdown.push_str(&block);
        }

        if configuration.show_rule_string_block
            && let Some(block) = self.pattern_block_markdown()
        {
            markdown.push_str(&block);
        }

        if configuration.show_rule_condition_block
            && let Some(block) = self.condition_block_markdown()
        {
            markdown.push_str(&block);
        }

        MarkupContent { kind: MarkupKind::Markdown, value: markdown }
    }

    /// Creates the Markdown representation of the rule's meta block.
    ///
    /// Returns `None` if the rule does not contain the meta block.
    fn meta_block_markdown(&self) -> Option<String> {
        Some(code_block!(
            self.rule
                .children()
                .find(|node| node.kind() == SyntaxKind::META_BLK)?
                // All children in METAS_BLK should be META_DEF.
                .children()
                .map(|node| node.text().to_string())
                .join("\n")
        ))
    }

    /// Creates the Markdown representation of the rule's pattern block,
    /// with all the patterns it declares, one per line.
    ///
    /// Returns `None` if the rule does not contain the pattern block.
    fn pattern_block_markdown(&self) -> Option<String> {
        Some(code_block!(
            "### Strings:",
            self.rule
                .children()
                .find(|node| node.kind() == SyntaxKind::PATTERNS_BLK)?
                // All children in PATTERNS_BLK should be PATTERN_DEF.
                .children()
                .filter(|node| node.kind() == SyntaxKind::PATTERN_DEF)
                .map(|node| node.text().to_string())
                .join("\n")
        ))
    }

    /// Creates the Markdown representation of the rule's condition.
    ///
    /// Returns `None` if the rule does not contain the condition block.
    fn condition_block_markdown(&self) -> Option<String> {
        Some(code_block!(
            "### Condition:",
            self.rule
                .children()
                .find(|node| node.kind() == SyntaxKind::CONDITION_BLK)?
                .children()
                .find(|node| node.kind() == SyntaxKind::BOOLEAN_EXPR)?
                .text()
                .to_string()
                .lines()
                .map(|line| line.trim_start())
                .join("\n")
        ))
    }
}
