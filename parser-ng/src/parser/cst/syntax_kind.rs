use crate::tokenizer::Token;

/// Each of the node types in a Concrete Syntax Tree (CST).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum SyntaxKind {
    CONDITION_KW,
    FALSE_KW,
    GLOBAL_KW,
    IMPORT_KW,
    META_KW,
    PRIVATE_KW,
    RULE_KW,
    TRUE_KW,

    COLON,
    EQUAL,
    L_BRACE,
    R_BRACE,

    WHITESPACE,
    NEWLINE,

    ERROR,
    IDENT,
    IMPORT_STMT,
    RULE_DECL,
    RULE_MODS,
    RULE_TAGS,
    CONDITION,
    META_DEF,
    META_DEFS,
    SOURCE_FILE,
}

impl From<SyntaxKind> for rowan::SyntaxKind {
    fn from(value: SyntaxKind) -> Self {
        rowan::SyntaxKind(value as u16)
    }
}

impl From<&Token> for SyntaxKind {
    fn from(token: &Token) -> Self {
        match token {
            // Keywords
            Token::CONDITION_KW(_) => SyntaxKind::CONDITION_KW,
            Token::FALSE_KW(_) => SyntaxKind::FALSE_KW,
            Token::GLOBAL_KW(_) => SyntaxKind::GLOBAL_KW,
            Token::IMPORT_KW(_) => SyntaxKind::IMPORT_KW,
            Token::META_KW(_) => SyntaxKind::META_KW,
            Token::PRIVATE_KW(_) => SyntaxKind::PRIVATE_KW,
            Token::RULE_KW(_) => SyntaxKind::RULE_KW,
            Token::TRUE_KW(_) => SyntaxKind::TRUE_KW,
            // Literals
            Token::FLOAT_LIT(_) => {
                todo!()
            }
            Token::INTEGER_LIT(_) => {
                todo!()
            }
            Token::STRING_LIT(_) => {
                todo!()
            }
            // Punctuation
            Token::COLON(_) => SyntaxKind::COLON,
            Token::EQUAL(_) => SyntaxKind::EQUAL,
            Token::L_BRACE(_) => SyntaxKind::L_BRACE,
            Token::R_BRACE(_) => SyntaxKind::R_BRACE,
            // Hex patterns
            Token::HEX_BYTE(_) => {
                todo!()
            }
            // Identifiers
            Token::IDENT(_) => SyntaxKind::IDENT,
            // Trivia
            Token::WHITESPACE(_) => SyntaxKind::WHITESPACE,
            Token::NEWLINE(_) => SyntaxKind::NEWLINE,
            Token::UNKNOWN(_) => {
                todo!()
            }
            Token::INVALID_UTF8(_) => {
                todo!()
            }
        }
    }
}
