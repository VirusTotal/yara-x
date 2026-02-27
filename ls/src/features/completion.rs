use std::sync::Arc;

use async_lsp::lsp_types::{
    CompletionContext, CompletionItem, CompletionItemKind,
    CompletionItemLabelDetails, CompletionTriggerKind, InsertTextFormat,
    InsertTextMode, Position, Url,
};
use itertools::Itertools;

#[cfg(feature = "full-compiler")]
use yara_x::mods::reflect::Type;
#[cfg(feature = "full-compiler")]
use yara_x::mods::{module_definition, module_names};
use yara_x_parser::cst::{Immutable, Node, SyntaxKind, Token, CST};

use crate::documents::storage::DocumentStorage;
use crate::utils::cst_traversal::{
    find_declaration, idents_declared_by_expr, non_error_parent,
    prev_non_trivia_token, rule_containing_token, token_at_position,
};

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
        #[cfg(feature = "full-compiler")]
        return Some(import_suggestions());
        #[cfg(not(feature = "full-compiler"))]
        return None;
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

    #[cfg(feature = "full-compiler")]
    if let Some(suggestions) = field_suggestions(&token) {
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

            // Identifiers from `for` or `with` statements
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
#[cfg(feature = "full-compiler")]
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

#[derive(Debug)]
enum Segment {
    Field(String),
    Index,
}

/// Collects completion suggestions for structure fields.
#[cfg(feature = "full-compiler")]
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

#[cfg(feature = "full-compiler")]
/// Given a token, returns the type of the structure that the token is part of.
///
/// This function traverses the CST backwards from the given token to determine
/// the full path to a field within a structure (e.g., `module.field.subfield`).
/// It then uses this path to look up the corresponding `Type` definition.
///
/// If the token is part of a `for` or `with` statement, it will try to resolve
/// the type from the declared variables in those statements.
///
/// Returns an `Option<Type>` representing the type of the structure or field
/// identified by the token. Returns `None` if the type cannot be determined.
fn get_struct(token: &Token<Immutable>) -> Option<Type> {
    let mut path = Vec::new();

    let mut curr = Some(token.clone());
    while let Some(token) = curr {
        match token.kind() {
            SyntaxKind::IDENT => {
                // If the identifier is a variable declared in a `for` or `with`
                // statement, we need to find the type of that variable.
                if let Some((_, declaration)) = find_declaration(&token) {
                    return get_type_from_declaration(
                        &declaration,
                        &token,
                        path.into_iter().rev(),
                    );
                }

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
    let mut current_kind = Type::Struct(definition);

    for segment in path.iter().rev().skip(1) {
        match segment {
            Segment::Field(name) => {
                match current_kind {
                    Type::Struct(struct_def) => {
                        // Find field
                        current_kind = struct_def
                            .fields()
                            .find(|field| field.name() == *name)?
                            .ty();
                    }
                    _ => return None, // Cannot access field of non-struct
                }
            }
            Segment::Index => {
                match current_kind {
                    Type::Array(inner) => {
                        current_kind = *inner;
                    }
                    Type::Map(_, value) => {
                        current_kind = *value;
                    }
                    _ => return None, // Cannot index non-array
                }
            }
        }
    }
    Some(current_kind)
}

#[cfg(feature = "full-compiler")]
/// Resolves the `Type` of an identifier declared within `for` or `with` statements.
///
/// This function is called when `get_struct` identifies an identifier that is
/// not a module name but rather a variable declared in a `for` or `with` expression.
/// It then attempts to deduce the type of this variable based on its declaration.
///
/// # Arguments
///
/// * `declaration` - The `Node` representing the `for` or `with` declaration.
/// * `ident` - The `Token` of the identifier whose type needs to be resolved.
/// * `path` - An iterator over `Segment`s representing the access path (fields,
///   array indices) applied to the declared variable.
///
/// # Returns
///
/// An `Option<Type>` representing the resolved type of the identifier. Returns `None`
/// if the type cannot be determined or if the access path is invalid for the type.
fn get_type_from_declaration(
    declaration: &Node<Immutable>,
    ident: &Token<Immutable>,
    path: impl Iterator<Item = Segment>,
) -> Option<Type> {
    match declaration.kind() {
        SyntaxKind::WITH_EXPR => {
            let with_decls = declaration
                .children()
                .find(|n| n.kind() == SyntaxKind::WITH_DECLS)?;

            for with_decl in with_decls.children() {
                let declared_ident = with_decl.first_token()?;
                if declared_ident.text() != ident.text() {
                    continue;
                }

                let mut current_type = get_struct(&with_decl.last_token()?)?;

                for segment in path {
                    match segment {
                        Segment::Field(name) => {
                            if let Type::Struct(struct_def) = current_type {
                                current_type = struct_def
                                    .fields()
                                    .find(|field| field.name() == name)?
                                    .ty()
                            } else {
                                return None;
                            }
                        }
                        Segment::Index => {
                            if let Type::Array(inner) = current_type {
                                current_type = *inner
                            } else {
                                return None;
                            }
                        }
                    }
                }
                return Some(current_type);
            }
            return None;
        }
        SyntaxKind::FOR_EXPR => {
            let colon = declaration
                .children_with_tokens()
                .find(|child| child.kind() == SyntaxKind::COLON)?
                .into_token()?;

            let iterable_last_token = prev_non_trivia_token(&colon)?;

            let iterable_type = get_struct(&iterable_last_token)?;

            let mut current_type = match iterable_type {
                Type::Array(inner) => *inner,
                Type::Map(_, value) => *value,
                _ => return None,
            };

            for segment in path {
                match segment {
                    Segment::Field(name) => {
                        if let Type::Struct(struct_def) = current_type {
                            current_type = struct_def
                                .fields()
                                .find(|field| field.name() == name)?
                                .ty()
                        } else {
                            return None;
                        }
                    }
                    Segment::Index => {
                        if let Type::Array(inner) = current_type {
                            current_type = *inner
                        } else {
                            return None;
                        }
                    }
                }
            }
            return Some(current_type);
        }
        _ => {}
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
fn ty_to_string(ty: &Type) -> String {
    match ty {
        Type::Integer => "integer".to_string(),
        Type::Float => "float".to_string(),
        Type::Bool => "bool".to_string(),
        Type::String => "string".to_string(),
        Type::Regexp => "regexp".to_string(),
        Type::Struct(_) => "struct".to_string(),
        Type::Func(_) => "func()".to_string(),
        Type::Array(inner) => format!("array<{}>", ty_to_string(inner)),
        Type::Map(key, value) => {
            format!("map<{},{}>", ty_to_string(key), ty_to_string(value))
        }
    }
}
