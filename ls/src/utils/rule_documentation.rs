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

#[cfg(test)]
mod tests {
    use yara_x_parser::cst::{CST, Utf8};

    use super::*;

    const RULE: &str = r#"rule test {
  meta:
    author = "me"
    date = "2026-10-06"
  strings:
    $a = "foo"
    $b = { 01 02 }
  condition:
    $a and $b
}"#;

    fn builder_for(rule: &str) -> RuleDocumentationBuilder {
        let cst = CST::from(rule);
        let rule = cst
            .root()
            .children()
            .find(|node| node.kind() == SyntaxKind::RULE_DECL)
            .expect("rule node");
        RuleDocumentationBuilder::new(rule)
    }

    fn config(strings: bool, condition: bool) -> DocumentationConfiguration {
        DocumentationConfiguration {
            show_rule_string_block: strings,
            show_rule_condition_block: condition,
        }
    }

    fn markdown(
        builder: &RuleDocumentationBuilder,
        strings: bool,
        condition: bool,
    ) -> String {
        builder.rule_markdown(&config(strings, condition)).value
    }

    #[test]
    fn test_rule_markdown_config_permutations() {
        assert_eq!(
            markdown(&builder_for(RULE), false, false),
            concat!(
                "## rule `test`\n",
                "```\n",
                "author = \"me\"\n",
                "date = \"2026-10-06\"\n",
                "```\n",
            )
        );

        assert_eq!(
            markdown(&builder_for(RULE), true, false),
            concat!(
                "## rule `test`\n",
                "```\n",
                "author = \"me\"\n",
                "date = \"2026-10-06\"\n",
                "```\n",
                "### Strings:\n",
                "\n",
                "```\n",
                "$a = \"foo\"\n",
                "$b = { 01 02 }\n",
                "```\n",
            )
        );

        assert_eq!(
            markdown(&builder_for(RULE), false, true),
            concat!(
                "## rule `test`\n",
                "```\n",
                "author = \"me\"\n",
                "date = \"2026-10-06\"\n",
                "```\n",
                "### Condition:\n",
                "\n",
                "```\n",
                "$a and $b\n",
                "```\n",
            )
        );

        assert_eq!(
            markdown(&builder_for(RULE), true, true),
            concat!(
                "## rule `test`\n",
                "```\n",
                "author = \"me\"\n",
                "date = \"2026-10-06\"\n",
                "```\n",
                "### Strings:\n",
                "\n",
                "```\n",
                "$a = \"foo\"\n",
                "$b = { 01 02 }\n",
                "```\n",
                "### Condition:\n",
                "\n",
                "```\n",
                "$a and $b\n",
                "```\n",
            )
        );
    }

    #[test]
    fn test_rule_markdown_without_meta_block() {
        let builder = builder_for("rule test { condition: true }");

        // No meta nor strings blocks; only the condition is rendered.
        assert_eq!(
            markdown(&builder, true, true),
            concat!(
                "## rule `test`\n",
                "### Condition:\n",
                "\n",
                "```\n",
                "true\n",
                "```\n",
            )
        );
    }

    #[test]
    fn test_pattern_single_markdown() {
        let builder = builder_for(RULE);

        let markdown =
            builder.pattern_single_markdown("$a").expect("pattern $a found");

        assert_eq!(
            markdown.value,
            "Pattern value is:\n\n```\n$a = \"foo\"\n```\n"
        );

        // The lookup ignores the sigil, so #a, @a and !a all match $a.
        for name in ["#a", "@a", "!a"] {
            let markdown =
                builder.pattern_single_markdown(name).expect("matches $a");
            assert!(markdown.value.contains("$a = \"foo\""));
        }
    }

    #[test]
    fn test_pattern_single_markdown_not_found() {
        let builder = builder_for(RULE);

        assert!(builder.pattern_single_markdown("$c").is_none());
        // Names shorter than two characters (sigil + identifier) can never
        // match a pattern.
        assert!(builder.pattern_single_markdown("").is_none());
        assert!(builder.pattern_single_markdown("$").is_none());
    }

    #[test]
    fn test_pattern_node_markdown() {
        let builder = builder_for(RULE);
        let pattern = builder
            .rule
            .children()
            .find(|node| node.kind() == SyntaxKind::PATTERNS_BLK)
            .expect("patterns block")
            .children()
            .find(|node| node.kind() == SyntaxKind::PATTERN_DEF)
            .expect("pattern def");

        let markdown =
            RuleDocumentationBuilder::pattern_node_markdown(&pattern);

        assert_eq!(markdown.kind, MarkupKind::Markdown);
        assert_eq!(
            markdown.value,
            "Pattern value is:\n\n```\n$a = \"foo\"\n```\n"
        );
    }

    #[test]
    fn test_from_token_inside_rule() {
        let cst = CST::from(RULE);
        // The token at line 0, column 6 is the rule identifier.
        let token = cst
            .root()
            .token_at_position::<Utf8, _>((0, 6))
            .expect("token found");

        let builder =
            RuleDocumentationBuilder::from_token(&token).expect("in rule");
        let value = markdown(&builder, false, false);
        assert!(value.starts_with("## rule `test`\n"));
    }

    #[test]
    fn test_from_token_outside_rule() {
        let cst =
            CST::from("include \"other.yar\"\nrule t { condition: true }");
        // The token at line 0, column 1 belongs to the include statement,
        // which is outside any rule.
        let token = cst
            .root()
            .token_at_position::<Utf8, _>((0, 1))
            .expect("token found");

        assert!(RuleDocumentationBuilder::from_token(&token).is_none());
    }
}
