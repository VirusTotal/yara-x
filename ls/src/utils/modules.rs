use yara_x::mods::module_definition;
use yara_x::mods::reflect::Type;
use yara_x_parser::{
    ast::{Expr, Lookup, NAryExpr},
    cst::{Immutable, Node, SyntaxKind, Token},
};

use crate::utils::cst_traversal::{find_declaration, prev_non_trivia_token};

#[derive(Debug)]
pub enum Segment {
    Field(String),
    Index,
}

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
pub fn get_type(token: &Token<Immutable>) -> Option<Type> {
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
                if let Some(prev) = prev_non_trivia_token(&token)
                    && prev.kind() == SyntaxKind::DOT
                {
                    curr = prev_non_trivia_token(&prev);
                    continue;
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
pub fn get_type_from_declaration(
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

                let mut current_type = get_type(&with_decl.last_token()?)?;

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
            let iterable_type = get_type(&iterable_last_token)?;

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
pub fn find_matching_left_bracket(
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

/// Resolves a `Type` from an AST expression
pub fn from_expr(expr: &Expr) -> Option<Type> {
    let segments = from_expr_inner(expr);

    let module_name = match segments.first()? {
        Segment::Field(s) => s,
        _ => return None,
    };

    // Lookup module
    let definition = module_definition(module_name)?;

    // Traverse
    let mut current_kind = Type::Struct(definition);

    for segment in segments.iter().skip(1) {
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

fn from_expr_inner(expr: &Expr) -> Vec<Segment> {
    match expr {
        Expr::FuncCall(func_call) => {
            if let Some(obj) = &func_call.object {
                let mut segments = from_expr_inner(obj);
                segments.push(Segment::Field(
                    func_call.identifier.name.to_string(),
                ));
                segments
            } else {
                vec![]
            }
        }
        Expr::FieldAccess(nary) => from_field_access(nary),
        Expr::Lookup(lookup) => from_lookup(lookup),
        Expr::Ident(ident) => {
            vec![Segment::Field(ident.name.to_string())]
        }
        _ => {
            vec![]
        }
    }
}

fn from_field_access(field_access: &NAryExpr) -> Vec<Segment> {
    let mut res = Vec::new();
    for operand in field_access.operands() {
        match operand {
            Expr::Ident(ident) => {
                res.push(Segment::Field(ident.name.to_string()));
            }
            Expr::Lookup(lookup) => {
                res.extend(from_lookup(lookup));
            }
            _ => {}
        }
    }
    res
}

fn from_lookup(lookup: &Lookup) -> Vec<Segment> {
    match &lookup.primary {
        Expr::Ident(ident) => {
            vec![Segment::Field(ident.name.to_string()), Segment::Index]
        }
        Expr::FieldAccess(nary) => {
            let mut res = from_field_access(nary);
            res.push(Segment::Index);
            res
        }
        _ => vec![],
    }
}

pub fn ty_to_string(ty: &Type) -> String {
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
