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

/// Removes the base indentation of a CST node from its continuation lines
/// while preserving any nested relative indentation.
fn dedent_node(node: &Node<Immutable>) -> String {
    let mut text = node.text().to_string();
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };

    if lines.clone().next().is_none() {
        let len = first.len();
        text.truncate(len);
        return text;
    }

    let min_continuation_indent = lines
        .clone()
        .filter(|line| !line.trim_ascii().is_empty())
        .map(|line| {
            line.chars().take_while(|c| matches!(c, ' ' | '\t')).count()
        })
        .min()
        .unwrap_or(0);

    let first_line_indent = node.first_token().and_then(|first_tok| {
        match first_tok.prev_token() {
            Some(tok)
                if tok.kind() == SyntaxKind::WHITESPACE
                    && tok.prev_token().is_none_or(|prev| {
                        prev.kind() == SyntaxKind::NEWLINE
                    }) =>
            {
                Some(tok.text().len())
            }
            Some(tok) if tok.kind() == SyntaxKind::NEWLINE => Some(0),
            None => Some(0),
            _ => None,
        }
    });

    let strip_indent = first_line_indent
        .map_or(min_continuation_indent, |indent| {
            indent.min(min_continuation_indent)
        });

    std::iter::once(first)
        .chain(lines.map(|line| {
            if line.trim_ascii().is_empty() {
                ""
            } else {
                &line[strip_indent..]
            }
        }))
        .join("\n")
}

/// Builder for the Markdown representation of a rule and its patterns.
pub(crate) struct RuleDocumentationBuilder {
    rule: Node<Immutable>,
}

impl RuleDocumentationBuilder {
    /// Creates a new builder for the given `RULE_DECL` node.
    pub(crate) fn new(rule: Node<Immutable>) -> Self {
        assert_eq!(rule.kind(), SyntaxKind::RULE_DECL);
        Self { rule }
    }

    /// Creates a new builder for the given token.
    ///
    /// Returns `None` if the token is not contained in some rule.
    pub(crate) fn from_token(token: &Token<Immutable>) -> Option<Self> {
        rule_containing_token(token).map(Self::new)
    }

    /// Creates the Markdown representation of the pattern identified as
    /// `name` string.
    ///
    /// Returns `None` if the rule doesn't declare such pattern.
    pub(crate) fn pattern_single_markdown(
        &self,
        name: &str,
    ) -> Option<MarkupContent> {
        let pattern = pattern_from_string(&self.rule, name)?;

        Some(Self::pattern_node_markdown(&pattern))
    }

    #[inline]
    pub(crate) fn pattern_node_markdown(
        pattern: &Node<Immutable>,
    ) -> MarkupContent {
        MarkupContent {
            kind: MarkupKind::Markdown,
            value: code_block!("Pattern value is:", dedent_node(pattern)),
        }
    }

    /// Creates the Markdown representation of the rule.
    pub(crate) fn rule_markdown(
        &self,
        configuration: &DocumentationConfiguration,
    ) -> MarkupContent {
        let ident = rule_ident(&self.rule);
        let name =
            ident.as_ref().map(|token| token.text()).unwrap_or_default();

        let mut markdown = format!("## rule `{name}`\n");

        if let Some(block) = self.meta_block_markdown() {
            markdown.push_str(&block);
        }

        if configuration.show_rule_strings_block
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
        let metas = self
            .rule
            .children()
            .find(|node| node.kind() == SyntaxKind::META_BLK)?
            // All children in META_BLK should be META_DEF.
            .children()
            .filter(|node| node.kind() == SyntaxKind::META_DEF)
            .map(|node| node.text())
            .join("\n");

        (!metas.is_empty()).then(|| code_block!(metas))
    }

    /// Creates the Markdown representation of the rule's pattern block,
    /// with all the patterns it declares, one per line.
    ///
    /// Returns `None` if the rule does not contain the pattern block.
    fn pattern_block_markdown(&self) -> Option<String> {
        let patterns = self
            .rule
            .children()
            .find(|node| node.kind() == SyntaxKind::PATTERNS_BLK)?
            // All children in PATTERNS_BLK should be PATTERN_DEF.
            .children()
            .filter(|node| node.kind() == SyntaxKind::PATTERN_DEF)
            .map(|node| dedent_node(&node))
            .join("\n");

        (!patterns.is_empty()).then(|| code_block!("### strings:", patterns))
    }

    /// Creates the Markdown representation of the rule's condition.
    ///
    /// Returns `None` if it failed to find the condition block.
    fn condition_block_markdown(&self) -> Option<String> {
        let boolean_expr = self
            .rule
            .children()
            .find(|node| node.kind() == SyntaxKind::CONDITION_BLK)?
            .children()
            .find(|node| node.kind() == SyntaxKind::BOOLEAN_EXPR)?;

        Some(code_block!("### condition:", dedent_node(&boolean_expr)))
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
            show_rule_strings_block: strings,
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
                "### strings:\n",
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
                "### condition:\n",
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
                "### strings:\n",
                "\n",
                "```\n",
                "$a = \"foo\"\n",
                "$b = { 01 02 }\n",
                "```\n",
                "### condition:\n",
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
                "### condition:\n",
                "\n",
                "```\n",
                "true\n",
                "```\n",
            )
        );
    }

    #[test]
    fn test_rule_markdown_multiline_nested_condition() {
        let rule = r#"rule nested {
  condition:
    for any i in (1..10) : (
      i > 5 and
      i < 8
    )
}"#;
        let builder = builder_for(rule);

        assert_eq!(
            markdown(&builder, false, true),
            concat!(
                "## rule `nested`\n",
                "### condition:\n",
                "\n",
                "```\n",
                "for any i in (1..10) : (\n",
                "  i > 5 and\n",
                "  i < 8\n",
                ")\n",
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
        // Names shorter than two characters (sigil + identifier), names
        // without a valid sigil, or multi-byte UTF-8 prefixes can never match.
        assert!(builder.pattern_single_markdown("").is_none());
        assert!(builder.pattern_single_markdown("$").is_none());
        assert!(builder.pattern_single_markdown("aa").is_none());
        assert!(builder.pattern_single_markdown("ä").is_none());
        assert!(builder.pattern_single_markdown("äa").is_none());
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
