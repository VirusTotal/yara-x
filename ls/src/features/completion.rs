use crate::utils::cst_traversal::{
    non_error_parent, prev_non_trivia_token, rule_containing_token,
    token_at_position,
};

use async_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails,
    InsertTextFormat, InsertTextMode, Position,
};

#[cfg(feature = "full-compiler")]
use yara_x::mods::module_definition;
#[cfg(feature = "full-compiler")]
use yara_x::mods::reflect::FieldKind;

use yara_x_parser::cst::{Immutable, Node, SyntaxKind, Token, CST};

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
    ("rule", Some("rule ${1:ident} {\n\tcondition:\n\t\t${2:true}\n}")),
    ("import", Some("import \"${1:}\"")),
    ("include", Some("include \"${1:}\"")),
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

pub fn completion(cst: &CST, pos: Position) -> Option<Vec<CompletionItem>> {
    // Get the token before cursor. There might be no token at cursor when the
    // cursor is at the end of the file. In this case, take the last token of the file.
    let token = token_at_position(cst, pos)
        .and_then(|token| token.prev_token())
        .or_else(|| cst.root().last_token())?;

    // If the token is a direct child of `SOURCE_FILE`, return top-level suggestions.
    if non_error_parent(&token)?.kind() == SyntaxKind::SOURCE_FILE {
        return Some(source_file_suggestions());
    }

    let prev_token = prev_non_trivia_token(&token)?;

    if let Some(pattern_def) =
        prev_token.ancestors().find(|n| n.kind() == SyntaxKind::PATTERN_DEF)
    {
        return Some(pattern_modifier_suggestions(pattern_def));
    }

    if prev_token.ancestors().any(|n| n.kind() == SyntaxKind::CONDITION_BLK) {
        return condition_suggestions(cst, token);
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
) -> Option<Vec<CompletionItem>> {
    let mut result = Vec::new();

    #[cfg(feature = "full-compiler")]
    if let Some(suggestions) = module_suggestions(&token) {
        return Some(suggestions);
    }

    match token.kind() {
        // Suggest completion of
        SyntaxKind::IDENT => {
            for rule_decl in cst
                .root()
                .children()
                .filter(|n| n.kind() == SyntaxKind::RULE_DECL)
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

            // Keywords
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

/// Collects completion suggestions outside any block.
fn source_file_suggestions() -> Vec<CompletionItem> {
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

#[cfg(feature = "full-compiler")]
fn module_suggestions(
    token: &Token<Immutable>,
) -> Option<Vec<CompletionItem>> {
    let mut curr;

    // Check if we are at a position that triggers completion.
    match token.kind() {
        SyntaxKind::DOT => {
            // structure. <cursor>
            curr = prev_non_trivia_token(token);
        }
        SyntaxKind::IDENT => {
            // structure.field <cursor>
            // We need to check if previous is DOT
            let prev = prev_non_trivia_token(token)?;
            if prev.kind() == SyntaxKind::DOT {
                // It is a field
                curr = prev_non_trivia_token(&prev);
            } else {
                return None;
            }
        }
        _ => return None,
    }

    #[derive(Debug)]
    enum Segment {
        Field(String),
        Index,
    }

    let mut path = Vec::new();

    while let Some(token) = curr {
        match token.kind() {
            SyntaxKind::IDENT => {
                path.push(Segment::Field(token.text().to_string()));
                // Look for previous DOT
                if let Some(prev) = prev_non_trivia_token(&token) {
                    if prev.kind() == SyntaxKind::DOT {
                        curr = prev_non_trivia_token(&prev);
                        continue;
                    }
                }
                // If no dot, we might have reached the start (module name)
                break;
            }
            SyntaxKind::R_BRACKET => {
                // Array access: field[index]
                path.push(Segment::Index);
                // Skip to L_BRACKET
                curr = find_matching_left_bracket(&token);
                // After finding [, look for previous token.
                // It should be the field name (IDENT).
                if let Some(c) = curr {
                    curr = prev_non_trivia_token(&c);
                }
                continue;
            }
            _ => break, // Unknown token, stop chain
        }
    }

    let module_name = match path.last()? {
        Segment::Field(s) => s,
        _ => return None,
    };

    // Lookup module
    let definition = module_definition(module_name)?;

    // Traverse
    let mut current_kind = FieldKind::Struct(definition);

    for segment in path.iter().rev().skip(1) {
        match segment {
            Segment::Field(name) => {
                match current_kind {
                    FieldKind::Struct(struct_def) => {
                        // Find field
                        current_kind = struct_def
                            .fields()
                            .find(|field| field.name() == name)?
                            .kind();
                    }
                    _ => return None, // Cannot access field of non-struct
                }
            }
            Segment::Index => {
                match current_kind {
                    FieldKind::Array(inner) => {
                        current_kind = *inner;
                    }
                    FieldKind::Map(_, value) => {
                        current_kind = *value;
                    }
                    _ => return None, // Cannot index non-array
                }
            }
        }
    }

    // Now `current_kind` is the type of the expression before the cursor.
    // We want to suggest fields if it is a Struct.
    if let FieldKind::Struct(def) = current_kind {
        let suggestions = def
            .fields()
            .map(|f| CompletionItem {
                label: f.name().to_string(),
                kind: Some(CompletionItemKind::FIELD),
                label_details: Some(CompletionItemLabelDetails {
                    description: Some(kind_to_string(&f.kind())),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect();
        return Some(suggestions);
    }

    None
}

/// Given a token that must be a closing (right) bracket, find the
/// corresponding opening (left) bracket.
#[cfg(feature = "full-compiler")]
fn find_matching_left_bracket(
    token: &Token<Immutable>,
) -> Option<Token<Immutable>> {
    assert_eq!(token.kind(), SyntaxKind::R_BRACKET);

    let mut depth = 1;
    let mut prev = token.prev_token();

    while let Some(token) = prev {
        match token.kind() {
            SyntaxKind::R_BRACKET => depth += 1,
            SyntaxKind::L_BRACKET => {
                depth -= 1;
                if depth == 0 {
                    return Some(token);
                }
            }
            _ => {}
        }
        prev = token.prev_token();
    }

    None
}

#[cfg(feature = "full-compiler")]
fn kind_to_string(k: &FieldKind) -> String {
    match k {
        FieldKind::Integer => "integer".to_string(),
        FieldKind::Float => "float".to_string(),
        FieldKind::Bool => "bool".to_string(),
        FieldKind::String => "string".to_string(),
        FieldKind::Bytes => "bytes".to_string(),
        FieldKind::Struct(_) => "struct".to_string(),
        FieldKind::Array(inner) => format!("array<{}>", kind_to_string(inner)),
        FieldKind::Map(key, value) => {
            format!("map<{},{}>", kind_to_string(key), kind_to_string(value))
        }
    }
}
