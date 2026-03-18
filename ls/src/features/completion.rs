use std::collections::HashSet;
use std::sync::Arc;

use async_lsp::lsp_types::{
    CompletionContext, CompletionItem, CompletionItemKind,
    CompletionItemLabelDetails, CompletionTriggerKind, InsertTextFormat,
    InsertTextMode, Position, Range, TextEdit, Url,
};

use itertools::Itertools;

use yara_x::mods::{module_names, reflect::Type};
use yara_x_parser::cst::{CST, Immutable, Node, SyntaxKind, Token};

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::{
    idents_declared_by_expr, non_error_parent, prev_non_trivia_token,
    rule_containing_token, token_at_position,
};

use crate::utils::modules::{get_struct, ty_to_string};

const PATTERN_MODS: &[(SyntaxKind, &[&str])] = &[
    (
        SyntaxKind::STRING_LIT,
        &[
            "ascii",
            "wide",
            "nocase",
            "private",
            "fullword",
            "base64",
            "base64wide",
            "xor",
        ],
    ),
    (SyntaxKind::REGEXP, &["ascii", "wide", "nocase", "private", "fullword"]),
    (SyntaxKind::HEX_PATTERN, &["private"]),
];

const RULE_KW_BLKS: [&str; 3] = ["meta", "strings", "condition"];

const SRC_SUGGESTIONS: [(&str, Option<&str>); 5] = [
    (
        "rule",
        Some(
            r#"rule ${1:ident} {
  strings:
    $${2:a} = "${3}"
  condition:
    $${2:a}${0}
 }"#,
        ),
    ),
    ("import", Some("import \"${1:}\"${0}")),
    ("include", Some("include \"${1:}\"${0}")),
    ("private", None),
    ("global", None),
];

const CONDITION_SUGGESTIONS: [(&str, Option<&str>); 16] = [
    ("and", None),
    ("or", None),
    ("all", None),
    ("any", None),
    ("none", None),
    ("of", None),
    ("at", Some("at ${1:expression}")),
    ("in", Some("in ${1:}..${2:}")),
    ("filesize", None),
    ("entrypoint", None),
    ("true", None),
    ("false", None),
    ("not", None),
    ("defined", None),
    ("for", Some("for ${1:quantifier} ${2:iterable} : ( ${3:expression} )")),
    ("with", Some("with ${1:declarations} : ( ${3:expression} )")),
];

pub fn completion(
    documents: Arc<DocumentStorage>,
    pos: Position,
    uri: Url,
    context: Option<CompletionContext>,
) -> Option<Vec<CompletionItem>> {
    let cst = &documents.get(&uri)?.cst;
    // Get the token before cursor. There might be no token at cursor when the
    // cursor is at the end of the file. In this case, take the last token of the file.
    let token = token_at_position(cst, pos)
        .and_then(|token| token.prev_token())
        .or_else(|| cst.root().last_token())?;

    // Trigger characters are: `.`, `!`, `$`, `@`, `#`.
    let is_trigger_character = context.is_some_and(|ctx| {
        ctx.trigger_kind == CompletionTriggerKind::TRIGGER_CHARACTER
    });

    // If the token is a direct child of `SOURCE_FILE`, return top-level suggestions.
    if !is_trigger_character
        && non_error_parent(&token)?.kind() == SyntaxKind::SOURCE_FILE
    {
        return Some(top_level_suggestions());
    }

    let prev_token = prev_non_trivia_token(&token)?;

    if prev_token.ancestors().any(|n| n.kind() == SyntaxKind::CONDITION_BLK) {
        return condition_suggestions(cst, token, documents.clone(), uri);
    }

    // Trigger characters are recognized in the condition block only.
    if is_trigger_character {
        return Some(vec![]);
    }

    if prev_token.kind() == SyntaxKind::IMPORT_KW {
        return Some(import_suggestions());
    }

    if let Some(pattern_def) =
        prev_token.ancestors().find(|n| n.kind() == SyntaxKind::PATTERN_DEF)
    {
        return Some(pattern_modifier_suggestions(pattern_def));
    }

    if prev_token.ancestors().any(|n| n.kind() == SyntaxKind::RULE_DECL) {
        return Some(rule_suggestions());
    }

    Some(vec![])
}

/// Collects completion suggestions for a condition block.
fn condition_suggestions(
    cst: &CST,
    token: Token<Immutable>,
    documents: Arc<DocumentStorage>,
    uri: Url,
) -> Option<Vec<CompletionItem>> {
    let mut result = Vec::new();

    if let Some(suggestions) = field_suggestions(&token) {
        return Some(suggestions);
    }

    match token.kind() {
        // Suggest completion of
        SyntaxKind::IDENT => {
            let root = cst.root();
            for rule_decl in
                root.children().filter(|n| n.kind() == SyntaxKind::RULE_DECL)
            {
                if let Some(rule_ident) = rule_decl
                    .children_with_tokens()
                    .find(|n| n.kind() == SyntaxKind::IDENT)
                    .and_then(|n| n.into_token())
                {
                    result.push(CompletionItem {
                        label: rule_ident.text().to_string(),
                        label_details: Some(CompletionItemLabelDetails {
                            description: Some("Rule".to_string()),
                            ..Default::default()
                        }),
                        kind: Some(CompletionItemKind::VARIABLE),
                        ..Default::default()
                    });
                }
            }
            result.extend(
                documents.included_rules(cst.root(), &uri).into_iter().map(
                    |(desc, token)| CompletionItem {
                        label: token.text().to_string(),
                        label_details: Some(CompletionItemLabelDetails {
                            description: Some(desc),
                            ..Default::default()
                        }),
                        kind: Some(CompletionItemKind::VARIABLE),
                        ..Default::default()
                    },
                ),
            );

            // Keywords.
            CONDITION_SUGGESTIONS.iter().for_each(|(kw, insert)| {
                result.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    insert_text_format: insert
                        .map(|_| InsertTextFormat::SNIPPET),
                    insert_text: insert
                        .map(|insert_text| insert_text.to_string()),
                    ..Default::default()
                });
            });

            // Identifiers from `for` or `with` statements.
            idents_declared_by_expr(&token).iter().for_each(|ident| {
                result.push(CompletionItem {
                    label: ident.text().to_string(),
                    label_details: Some(CompletionItemLabelDetails {
                        description: Some("Variable".to_string()),
                        ..Default::default()
                    }),
                    kind: Some(CompletionItemKind::VARIABLE),
                    ..Default::default()
                })
            });

            // Collect already imported modules.
            let imported = root
                .children()
                .filter_map(|node| {
                    if node.kind() == SyntaxKind::IMPORT_STMT {
                        // The last token in IMPORT_STMT is a STRING_LIT with
                        // the module name.
                        node.last_token()
                    } else {
                        None
                    }
                })
                .map(|module_name| {
                    // Strip the quotes from the module name.
                    module_name.text().trim_matches('"').to_string()
                })
                .collect::<HashSet<String>>();

            // Suggest module names.
            module_names().for_each(|module_name| {
                // Automatically imports the module if it is not already imported.
                let additional_text_edits = if imported.contains(module_name) {
                    None
                } else {
                    Some(vec![TextEdit {
                        range: Range {
                            start: Position { line: 0, character: 0 },
                            end: Position { line: 0, character: 0 },
                        },
                        new_text: format!("import \"{}\"\n", module_name),
                    }])
                };
                result.push(CompletionItem {
                    label: module_name.to_string(),
                    kind: Some(CompletionItemKind::MODULE),
                    additional_text_edits,
                    ..Default::default()
                })
            });
        }
        SyntaxKind::PATTERN_IDENT
        | SyntaxKind::PATTERN_COUNT
        | SyntaxKind::PATTERN_OFFSET
        | SyntaxKind::PATTERN_LENGTH => {
            let pattern_defs = rule_containing_token(&token)?
                .children()
                .find(|node| node.kind() == SyntaxKind::PATTERNS_BLK)?
                .children();

            for pattern_def in pattern_defs {
                if let Some(pattern_ident) = pattern_def
                    .children_with_tokens()
                    .find(|n| n.kind() == SyntaxKind::PATTERN_IDENT)
                    .and_then(|n| n.into_token())
                {
                    result.push(CompletionItem {
                        label: String::from(&pattern_ident.text()[1..]),
                        label_details: Some(CompletionItemLabelDetails {
                            description: Some("Pattern".to_string()),
                            ..Default::default()
                        }),
                        kind: Some(CompletionItemKind::TEXT),
                        ..Default::default()
                    });
                }
            }
        }
        // Do not propose keywords for condition block after a dot.
        SyntaxKind::DOT => {}
        _ => {
            CONDITION_SUGGESTIONS.iter().for_each(|(kw, insert)| {
                result.push(CompletionItem {
                    label: kw.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    insert_text_format: insert
                        .map(|_| InsertTextFormat::SNIPPET),
                    insert_text: insert
                        .map(|insert_text| insert_text.to_string()),
                    ..Default::default()
                });
            });
        }
    }

    Some(result)
}

/// Collects completion suggestions for import statements.
fn import_suggestions() -> Vec<CompletionItem> {
    module_names()
        .map(|name| CompletionItem {
            label: name.to_string(),
            preselect: Some(true),
            kind: Some(CompletionItemKind::MODULE),
            ..Default::default()
        })
        .collect()
}

/// Collects completion suggestions outside any block.
fn top_level_suggestions() -> Vec<CompletionItem> {
    // Propose import or rule definition with snippet
    SRC_SUGGESTIONS
        .map(|(label, insert_text)| CompletionItem {
            label: label.to_string(),
            kind: if insert_text.is_none() {
                Some(CompletionItemKind::KEYWORD)
            } else {
                Some(CompletionItemKind::METHOD)
            },
            insert_text_mode: insert_text
                .map(|_| InsertTextMode::ADJUST_INDENTATION),
            insert_text_format: insert_text.map(|_| InsertTextFormat::SNIPPET),
            insert_text: insert_text
                .map(|insert_text| insert_text.to_string()),
            ..Default::default()
        })
        .into_iter()
        .collect()
}

/// Collects completion suggestions for pattern modifiers.
fn pattern_modifier_suggestions(node: Node<Immutable>) -> Vec<CompletionItem> {
    for (kind, valid_modifiers) in PATTERN_MODS {
        if node.children_with_tokens().any(|child| child.kind() == *kind) {
            return valid_modifiers
                .iter()
                .map(|modifier| CompletionItem {
                    label: modifier.to_string(),
                    kind: Some(CompletionItemKind::KEYWORD),
                    ..Default::default()
                })
                .collect();
        }
    }
    vec![]
}

/// Collects completion suggestions for different blocks of the rule.
fn rule_suggestions() -> Vec<CompletionItem> {
    RULE_KW_BLKS
        .iter()
        .map(|kw| CompletionItem {
            label: kw.to_string(),
            label_details: Some(CompletionItemLabelDetails {
                description: Some(format!("Block of {kw}")),
                ..Default::default()
            }),
            kind: Some(CompletionItemKind::KEYWORD),
            insert_text_mode: Some(InsertTextMode::ADJUST_INDENTATION),
            insert_text: Some(format!("{kw}:\n\t")),
            ..Default::default()
        })
        .collect()
}

/// Collects completion suggestions for structure fields.
fn field_suggestions(token: &Token<Immutable>) -> Option<Vec<CompletionItem>> {
    // Check if we are at a position that triggers completion.
    let token = match token.kind() {
        SyntaxKind::DOT => {
            // structure. <cursor>
            prev_non_trivia_token(token)
        }
        SyntaxKind::IDENT => {
            // structure.field <cursor>
            // We need to check if previous is DOT
            prev_non_trivia_token(token)
                .filter(|t| t.kind() == SyntaxKind::DOT)
                .and_then(|t| prev_non_trivia_token(&t))
        }
        _ => None,
    }?;

    let current_struct = match get_struct(&token)? {
        Type::Struct(s) => s,
        _ => return None,
    };

    // Now `current_struct` is the structure before the cursor.
    // We want to suggest fields for this structure.
    let suggestions = current_struct
        .fields()
        .flat_map(|f| {
            let name = f.name();
            let ty = f.ty();

            if let Type::Func(ref func_def) = ty {
                func_def
                    .signatures
                    .iter()
                    .map(|sig| {
                        let arg_types = sig
                            .args
                            .iter()
                            .map(ty_to_string)
                            .collect::<Vec<_>>();

                        let args_template = arg_types
                            .iter()
                            .enumerate()
                            .map(|(n, arg_type)| {
                                format!("${{{}:{arg_type}}}", n + 1)
                            })
                            .join(",");

                        CompletionItem {
                            label: format!(
                                "{}({})",
                                name,
                                arg_types.join(", ")
                            ),
                            kind: Some(CompletionItemKind::METHOD),
                            insert_text: Some(format!(
                                "{name}({args_template})",
                            )),
                            insert_text_format: Some(
                                InsertTextFormat::SNIPPET,
                            ),
                            label_details: Some(CompletionItemLabelDetails {
                                description: Some(ty_to_string(&ty)),
                                ..Default::default()
                            }),
                            documentation: sig.description.as_ref().map(
                                |docs| {
                                    async_lsp::lsp_types::Documentation::MarkupContent(
                                        async_lsp::lsp_types::MarkupContent {
                                            kind: async_lsp::lsp_types::MarkupKind::Markdown,
                                            value: format!(
                                                "## `{}({}) -> {}`\n\n{}",
                                                name,
                                                sig.args
                                                    .iter()
                                                    .map(ty_to_string)
                                                    .join(", "),
                                                ty_to_string(&sig.ret),
                                                docs
                                            ),
                                        },
                                    )
                                },
                            ),
                            ..Default::default()
                        }
                    })
                    .collect()
            } else {
                let insert_text = match &ty {
                    Type::Array(_) => format!("{name}[${{1}}]${{2}}"),
                    _ => name.to_string(),
                };

                vec![CompletionItem {
                    label: name.to_string(),
                    kind: Some(CompletionItemKind::FIELD),
                    insert_text: Some(insert_text),
                    insert_text_format: Some(InsertTextFormat::SNIPPET),
                    label_details: Some(CompletionItemLabelDetails {
                        description: Some(ty_to_string(&ty)),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]
            }
        })
        .collect();

    Some(suggestions)
}
