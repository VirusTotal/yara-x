use async_lsp::lsp_types::{
    HoverContents, MarkupContent, MarkupKind, Position,
};
use yara_x_parser::cst::{
    Immutable, Mutable, Node, NodeOrToken, SyntaxKind, Utf16, CST,
};

use crate::utils::cst_traversal::{
    pattern_from_strings, rule_containing_token, rule_from_ident,
};

/// Builder for hover markdown representation of a rule.
struct RuleHoverBuilder {
    name: String,
    metas: Option<Node<Immutable>>,
    strings: Option<Node<Immutable>>,
    condition: Option<Node<Mutable>>,
}

impl RuleHoverBuilder {
    /// Creates a new RuleHoverBuilder with the given rule identifier.
    pub fn new(name: &str) -> Self {
        RuleHoverBuilder {
            name: String::from(name),
            metas: None,
            strings: None,
            condition: None,
        }
    }

    /// Creates the markdown representation of the rule.
    /// It includes the rule name, metas, strings, and condition.
    pub fn get_markdown_representation(&self) -> String {
        format!(
            "#### Rule `{name}`\n\
            {metas}\
            #### Strings\n\
            {strings}\
            #### Condition\n\
            ```\n{condition}\n```\
            ",
            name = self.name,
            metas = self.process_metas().unwrap_or_default(),
            strings = self.process_strings().unwrap_or_default(),
            condition = self
                .process_condition()
                .unwrap_or_default()
                //Trim indents
                .split_inclusive('\n')
                .fold(String::new(), |mut acc, line| {
                    acc.push_str(line.trim_start());
                    acc
                })
        )
    }

    /// Processes the meta block and returns its markdown representation.
    fn process_metas(&self) -> Option<String> {
        let children = self.metas.clone()?.children();
        Some(
            children
                .filter(|node| node.kind() == SyntaxKind::META_DEF)
                .map(|node| format!("{}\n\n", node.text()))
                .collect(),
        )
    }

    /// Processes the strings block and returns its markdown representation.
    fn process_strings(&self) -> Option<String> {
        let children = self.strings.clone()?.children();
        Some(
            children
                //All children in PATTERNS_BLK Node should be PATTERN_DEF
                .map(|pattern_def| format!("`{}`\n\n", pattern_def.text()))
                .collect(),
        )
    }

    /// Processes the condition block and returns its markdown representation.
    fn process_condition(&self) -> Option<String> {
        let base = self.condition.clone()?;

        // Detaches `condition:` part
        let cond_prefix: Vec<NodeOrToken<Mutable>> = base
            .children_with_tokens()
            .take_while(|node_or_token| {
                node_or_token.kind() == SyntaxKind::WHITESPACE
                    || node_or_token.kind() == SyntaxKind::COLON
                    || node_or_token.kind() == SyntaxKind::NEWLINE
                    || node_or_token.kind() == SyntaxKind::CONDITION_KW
            })
            .collect();

        for node_or_token in cond_prefix {
            node_or_token.detach();
        }

        Some(format!("{}", base.text()))
    }

    /// Sets the meta block of the rule.
    pub fn set_metas(&mut self, meta: Node<Immutable>) {
        self.metas = Some(meta);
    }

    /// Sets the strings block of the rule.
    pub fn set_strings(&mut self, strings: Node<Immutable>) {
        self.strings = Some(strings);
    }

    /// Sets the condition block of the rule.
    pub fn set_condition(&mut self, condition: Node<Mutable>) {
        self.condition = Some(condition);
    }
}

pub fn hover(cst: &CST, pos: Position) -> Option<HoverContents> {
    // Find the token at the position where the user is hovering.
    let token = cst.root().token_at_position::<Utf16, _>((
        pos.line as usize,
        pos.character as usize,
    ))?;

    #[allow(irrefutable_let_patterns)]
    match token.kind() {
        // Pattern identifiers
        // PATTERN_IDENT($a) PATTERN_COUNT(#a) PATTERN_OFFSET(@a) PATTERN_LENGTH(!a)
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let rule = rule_containing_token(&token)?;

            let pattern = pattern_from_strings(&rule, token.text())?;

            Some(HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: format!("Pattern value is:\n\n`{}`", pattern.text()),
            }))
        }
        // Rule identifiers
        SyntaxKind::IDENT => {
            let rule = rule_from_ident(cst, token.text())?;
            let mut builder = RuleHoverBuilder::new(token.text());

            for child in rule.children() {
                match child.kind() {
                    SyntaxKind::META_BLK => {
                        builder.set_metas(child);
                    }
                    SyntaxKind::PATTERNS_BLK => {
                        builder.set_strings(child);
                    }
                    SyntaxKind::CONDITION_BLK => {
                        builder.set_condition(child.into_mut());
                    }
                    _ => {}
                }
            }

            Some(HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: builder.get_markdown_representation(),
            }))
        }
        _ => None,
    }
}
