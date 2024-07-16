use crate::Span;

#[derive(Debug, PartialEq, Eq)]
/// Error occurred while parsing the YARA source code.
pub enum Error {
    SyntaxError { message: String, span: Span },
    InvalidInteger { message: String, span: Span },
    InvalidFloat { message: String, span: Span },
    InvalidRegexpModifier { message: String, span: Span },
    InvalidEscapeSequence { message: String, span: Span },
    InvalidUTF8(Span),
    UnexpectedEscapeSequence(Span),
}
