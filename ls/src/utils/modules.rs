use std::collections::HashSet;

use yara_x::mods::module_definition;
use yara_x::mods::reflect::Type;
use yara_x_parser::{
    Span,
    ast::{Expr, Lookup, NAryExpr},
    cst::{Immutable, Node, SyntaxKind, Token},
};

use crate::utils::cst_traversal::{find_declaration, prev_non_trivia_token};

/// Upper bound on nested `with`/`for` variable alias chains resolved by
/// [`get_type`] to prevent stack overflows on deeply chained declarations.
const MAX_TYPE_RESOLUTION_DEPTH: usize = 64;

#[derive(Debug)]
pub enum Segment {
    Field(String),
    Index,
}

/// The result of resolving the type of an expression that refers to a
/// module's field (e.g. `pe.sections[0].name`).
#[derive(Debug)]
pub struct ResolvedType {
    /// The type of the field.
    pub ty: Type,
    /// The name of the module where the field comes from (e.g. `pe`).
    pub module: String,
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
/// Returns a [`ResolvedType`] containing the type of the structure or field
/// identified by the token, together with the name of the module it belongs
/// to. Returns `None` if the type cannot be determined.
pub fn get_type(token: &Token<Immutable>) -> Option<ResolvedType> {
    let mut visited = HashSet::new();
    get_type_inner(token, &mut visited)
}

fn get_type_inner(
    token: &Token<Immutable>,
    visited: &mut HashSet<Span>,
) -> Option<ResolvedType> {
    let mut path = Vec::new();
    let mut curr = Some(token.clone());

    while let Some(token) = curr {
        match token.kind() {
            SyntaxKind::IDENT => {
                // If the identifier is a variable declared in a `for` or `with`
                // statement, we need to find the type of that variable.
                if let Some((declared_ident, declaration)) =
                    find_declaration(&token)
                {
                    if visited.len() >= MAX_TYPE_RESOLUTION_DEPTH
                        || !visited.insert(declared_ident.span())
                    {
                        return None;
                    }
                    return get_type_from_declaration(
                        &declaration,
                        &declared_ident,
                        path.into_iter().rev(),
                        visited,
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

    // The path is stored in reverse order, so the module name is the last
    // segment. Take ownership of it to avoid cloning it later.
    let module_name = match path.pop()? {
        Segment::Field(s) => s,
        _ => return None,
    };

    // Lookup module
    let definition = module_definition(&module_name)?;

    // Traverse
    let mut current_kind = Type::Struct(definition);

    for segment in path.iter().rev() {
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

    Some(ResolvedType { ty: current_kind, module: module_name })
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
/// A [`ResolvedType`] containing the resolved type of the identifier and the
/// module it comes from. Returns `None` if the type cannot be determined or if
/// the access path is invalid for the type.
fn get_type_from_declaration(
    declaration: &Node<Immutable>,
    ident: &Token<Immutable>,
    path: impl Iterator<Item = Segment>,
    visited: &mut HashSet<Span>,
) -> Option<ResolvedType> {
    match declaration.kind() {
        SyntaxKind::WITH_EXPR => {
            let with_decls = declaration
                .children()
                .find(|n| n.kind() == SyntaxKind::WITH_DECLS)?;

            let mut target_decl = None;
            for with_decl in with_decls
                .children()
                .filter(|n| n.kind() == SyntaxKind::WITH_DECL)
            {
                let Some(declared_ident) = with_decl
                    .first_token()
                    .filter(|t| t.kind() == SyntaxKind::IDENT)
                else {
                    continue;
                };
                if declared_ident.span() == ident.span() {
                    target_decl = Some(with_decl);
                    break;
                }
                if declared_ident.text() == ident.text() {
                    target_decl = Some(with_decl);
                }
            }

            let with_decl = target_decl?;
            let eq = with_decl
                .children_with_tokens()
                .find(|child| child.kind() == SyntaxKind::EQUAL)?
                .into_token()?;

            let mut expr_last_token = with_decl.last_token()?;
            if matches!(
                expr_last_token.kind(),
                SyntaxKind::NEWLINE
                    | SyntaxKind::WHITESPACE
                    | SyntaxKind::COMMENT
            ) {
                expr_last_token = prev_non_trivia_token(&expr_last_token)?;
            }
            if expr_last_token.span().start() < eq.span().end() {
                return None;
            }

            let ResolvedType { ty: mut current_type, module } =
                get_type_inner(&expr_last_token, visited)?;

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
                    Segment::Index => match current_type {
                        Type::Array(inner) => current_type = *inner,
                        Type::Map(_, value) => current_type = *value,
                        _ => return None,
                    },
                }
            }
            return Some(ResolvedType { ty: current_type, module });
        }
        SyntaxKind::FOR_EXPR => {
            let in_kw = declaration
                .children_with_tokens()
                .find(|child| child.kind() == SyntaxKind::IN_KW)?
                .into_token()?;

            let colon = declaration
                .children_with_tokens()
                .find(|child| child.kind() == SyntaxKind::COLON)?
                .into_token()?;

            let iterable_last_token = prev_non_trivia_token(&colon)?;
            if iterable_last_token.span().start() < in_kw.span().end() {
                return None;
            }

            let ResolvedType { ty: iterable_type, module } =
                get_type_inner(&iterable_last_token, visited)?;

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
                    Segment::Index => match current_type {
                        Type::Array(inner) => current_type = *inner,
                        Type::Map(_, value) => current_type = *value,
                        _ => return None,
                    },
                }
            }
            return Some(ResolvedType { ty: current_type, module });
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
        Type::Struct(s) if s.is_enum() => "enum".to_string(),
        Type::Struct(_) => "struct".to_string(),
        Type::Func(_) => "func()".to_string(),
        Type::Array(inner) => format!("array<{}>", ty_to_string(inner)),
        Type::Map(key, value) => {
            format!("map<{},{}>", ty_to_string(key), ty_to_string(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yara_x_parser::cst::{CST, NodeOrToken};

    fn find_tokens(
        node: &Node<Immutable>,
        target: &str,
    ) -> Vec<Token<Immutable>> {
        let mut tokens = Vec::new();
        let mut stack = vec![NodeOrToken::Node(node.clone())];
        while let Some(nt) = stack.pop() {
            match nt {
                NodeOrToken::Node(n) => stack.extend(n.children_with_tokens()),
                NodeOrToken::Token(t) => {
                    if t.text() == target {
                        tokens.push(t);
                    }
                }
            }
        }
        tokens
    }

    #[test]
    fn test_ty_to_string() {
        assert_eq!(ty_to_string(&Type::Integer), "integer");
        assert_eq!(ty_to_string(&Type::Float), "float");
        assert_eq!(ty_to_string(&Type::Bool), "bool");
        assert_eq!(ty_to_string(&Type::String), "string");
        assert_eq!(ty_to_string(&Type::Regexp), "regexp");
        assert_eq!(
            ty_to_string(&Type::Array(Box::new(Type::Integer))),
            "array<integer>"
        );
        assert_eq!(
            ty_to_string(&Type::Map(
                Box::new(Type::String),
                Box::new(Type::Integer)
            )),
            "map<string,integer>"
        );
    }

    #[test]
    fn test_find_matching_left_bracket() {
        let text = "rule test { condition: arr[1][2] == 0 }";
        let cst = CST::from(text);
        let root = cst.root();

        let mut stack = vec![NodeOrToken::Node(root)];
        let mut r_bracket = None;
        while let Some(nt) = stack.pop() {
            match nt {
                NodeOrToken::Node(n) => stack.extend(n.children_with_tokens()),
                NodeOrToken::Token(t) => {
                    if t.kind() == SyntaxKind::R_BRACKET {
                        r_bracket = Some(t);
                        break;
                    }
                }
            }
        }

        let l_bracket = find_matching_left_bracket(&r_bracket.unwrap())
            .expect("matching left bracket");
        assert_eq!(l_bracket.kind(), SyntaxKind::L_BRACKET);
    }

    #[test]
    fn test_get_type_and_from_expr() {
        let text = "import \"pe\"\nrule test { condition: pe.characteristics == 0 and pe.sections[0].name == \".text\" }";
        let cst = CST::from(text);
        let root = cst.root();

        let char_token = find_tokens(&root, "characteristics").pop().unwrap();
        let resolved = get_type(&char_token).expect("characteristics type");
        assert!(matches!(resolved.ty, Type::Integer));
        assert_eq!(resolved.module, "pe");

        let name_token = find_tokens(&root, "name").first().unwrap().clone();
        let resolved = get_type(&name_token).expect("sections[0].name type");
        assert!(matches!(resolved.ty, Type::String));
        assert_eq!(resolved.module, "pe");
    }

    #[test]
    fn test_get_type_from_declaration_loop() {
        let text = "import \"pe\"\nrule test {\n  condition:\n    for any s in pe.sections : ( s.name == \".text\" ) and with e = pe.entry_point : ( e > 0 )\n}";
        let cst = CST::from(text);
        let root = cst.root();

        let s_tokens = find_tokens(&root, "s");
        let s_token = s_tokens.first().unwrap();

        let resolved = get_type(s_token).expect("type of s in for loop");
        assert!(matches!(resolved.ty, Type::Struct(_)));
        assert_eq!(resolved.module, "pe");

        let name_tokens = find_tokens(&root, "name");
        let name_token = name_tokens.first().unwrap();

        let resolved = get_type(name_token).expect("type of s.name in loop");
        assert!(matches!(resolved.ty, Type::String));
        assert_eq!(resolved.module, "pe");
    }

    #[test]
    fn test_get_type_cyclic_and_incomplete_declarations() {
        let cases = [
            // Self-referential `with` initializer.
            "rule r { condition: with a = a : ( a.foo == 1 ) }",
            // Mutually referencing `with` initializers.
            "rule r { condition: with a = b, b = a : ( a.foo == b.foo ) }",
            // Self-referential `for` iterable.
            "rule r { condition: for any s in s : ( s.foo == 1 ) }",
            // Incomplete `with` and `for` declarations while editing.
            "rule r { condition: with a : ( a.foo == 1 ) }",
            "rule r { condition: with a = : ( a.foo == 1 ) }",
            "rule r { condition: for any s : ( s.foo == 1 ) }",
            "rule r { condition: for any s in : ( s.foo == 1 ) }",
        ];

        for text in cases {
            let cst = CST::from(text);
            let root = cst.root();
            let mut stack = vec![NodeOrToken::Node(root)];
            while let Some(nt) = stack.pop() {
                match nt {
                    NodeOrToken::Node(n) => {
                        stack.extend(n.children_with_tokens())
                    }
                    NodeOrToken::Token(t) if t.kind() == SyntaxKind::IDENT => {
                        assert!(get_type(&t).is_none());
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn test_get_type_shadowing_and_deep_chain() {
        // `for` variable shadowing an outer `with` variable used as its iterable.
        let text = "import \"pe\"\nrule r { condition: with s = pe.sections : ( for any s in s : ( s.name == \".text\" ) ) }";
        let cst = CST::from(text);
        let root = cst.root();
        let name_token = find_tokens(&root, "name").pop().unwrap();
        let resolved = get_type(&name_token).expect("type of shadowed s.name");
        assert!(matches!(resolved.ty, Type::String));
        assert_eq!(resolved.module, "pe");

        // Redeclared `with` variable in the same `with` block.
        let text = "import \"pe\"\nrule r { condition: with s = pe.entry_point, s = pe.sections[0] : ( s.name == \".text\" ) }";
        let cst = CST::from(text);
        let root = cst.root();
        let name_token = find_tokens(&root, "name").pop().unwrap();
        let resolved =
            get_type(&name_token).expect("type of redeclared s.name");
        assert!(matches!(resolved.ty, Type::String));
        assert_eq!(resolved.module, "pe");

        // Deep chain exceeding `MAX_TYPE_RESOLUTION_DEPTH` must return `None`
        // cleanly without overflowing the stack.
        let mut decls = String::from("a0 = pe.sections[0]");
        for i in 1..=200 {
            decls.push_str(&format!(", a{i} = a{}", i - 1));
        }
        let deep = format!(
            "import \"pe\"\nrule r {{ condition: with {decls} : ( a200.name == \".text\" ) }}"
        );
        let cst = CST::from(deep.as_str());
        let root = cst.root();
        let name_token = find_tokens(&root, "name").pop().unwrap();
        assert!(get_type(&name_token).is_none());
    }
}
