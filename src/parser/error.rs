use super::GrammarRule;
use crate::parser::{Ident, SourceCode, Span};
use ariadne::{Color, Label, ReportKind, Source};
use pest::error::ErrorVariant::{CustomError, ParsingError};
use pest::error::InputLocation;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Range;
use yansi::Style;

/// An error occurred while parsing YARA rules.
pub struct Error {
    pub(crate) report: String,
}

impl Error {
    pub fn syntax_error_message<F>(
        expected: &[GrammarRule],
        unexpected: &[GrammarRule],
        mut f: F,
    ) -> String
    where
        F: FnMut(&GrammarRule) -> &str,
    {
        // Remove COMMENT and WHITESPACE from the lists of expected and not
        // expected rules. We don't want error messages like:
        //
        //    expected identifier or COMMENT
        //    expected { or WHITESPACE
        //
        // The alternative solution is silencing those rules in grammar.pest,
        // but that means that Pest will completely ignore them and we won't
        // get comments nor spaces in the parse tree. We want those rules in
        // the parse tree, but we don't want them in error messages. This is
        // probably an area of improvement for Pest.
        let expected: Vec<&GrammarRule> = expected
            .iter()
            .filter(|&&r| {
                r != GrammarRule::COMMENT && r != GrammarRule::WHITESPACE
            })
            .collect();

        let unexpected: Vec<&GrammarRule> = unexpected
            .iter()
            .filter(|&&r| {
                r != GrammarRule::COMMENT && r != GrammarRule::WHITESPACE
            })
            .collect();

        match (unexpected.is_empty(), expected.is_empty()) {
            (false, false) => format!(
                "unexpected {}; expected {}",
                Self::enumerate_grammar_rules(&unexpected, &mut f),
                Self::enumerate_grammar_rules(&expected, &mut f)
            ),
            (false, true) => {
                format!(
                    "unexpected {}",
                    Self::enumerate_grammar_rules(&unexpected, &mut f)
                )
            }
            (true, false) => {
                format!(
                    "expected {}",
                    Self::enumerate_grammar_rules(&expected, &mut f)
                )
            }
            (true, true) => "unknown parsing error".to_owned(),
        }
    }

    pub fn enumerate_grammar_rules<F>(
        rules: &[&GrammarRule],
        f: &mut F,
    ) -> String
    where
        F: FnMut(&GrammarRule) -> &str,
    {
        // All grammar rules in `rules` are mapped using `f`.
        let mut strings = rules.iter().map(|rule| f(rule)).collect::<Vec<_>>();

        // Sort alphabetically.
        strings.sort();

        // Deduplicate repeated items.
        strings.dedup();

        match strings.len() {
            1 => strings[0].to_owned(),
            2 => format!("{} or {}", strings[0], strings[1]),
            l => {
                format!(
                    "{}, or {}",
                    strings[..l - 1].join(", "),
                    strings[l - 1]
                )
            }
        }
    }

    /// Given a parser rule returns a more appropriate string that will be used
    /// in error messages.
    pub fn printable_string(rule: &GrammarRule) -> &str {
        match rule {
            // Keywords
            GrammarRule::k_ALL => "`all`",
            GrammarRule::k_ANY => "`any`",
            GrammarRule::k_ASCII => "`ascii`",
            GrammarRule::k_AT => "`at`",
            GrammarRule::k_BASE64 => "`base64`",
            GrammarRule::k_BASE64WIDE => "`base64wide`",
            GrammarRule::k_CONDITION => "`condition`",
            GrammarRule::k_FALSE => "`false`",
            GrammarRule::k_FILESIZE => "`filesize`",
            GrammarRule::k_FOR => "`for`",
            GrammarRule::k_FULLWORD => "`fullword`",
            GrammarRule::k_GLOBAL => "`global`",
            GrammarRule::k_IMPORT => "`import`",
            GrammarRule::k_IN => "`in`",
            GrammarRule::k_META => "`meta`",
            GrammarRule::k_NOCASE => "`nocase`",
            GrammarRule::k_NOT => "`not`",
            GrammarRule::k_OF => "`of`",
            GrammarRule::k_PRIVATE => "`private`",
            GrammarRule::k_RULE => "`rule`",

            GrammarRule::k_STRINGS => "`strings`",
            GrammarRule::k_THEM => "`them`",
            GrammarRule::k_TRUE => "`true`",
            GrammarRule::k_WIDE => "`wide`",
            GrammarRule::k_XOR => "`xor`",

            GrammarRule::boolean_expr | GrammarRule::boolean_term => {
                "boolean expression"
            }
            GrammarRule::expr
            | GrammarRule::primary_expr
            | GrammarRule::term => "expression",

            GrammarRule::hex_byte => "byte",
            GrammarRule::hex_pattern => "bytes",
            GrammarRule::ident => "identifier",
            GrammarRule::integer_lit => "number",
            GrammarRule::float_lit => "number",
            GrammarRule::rule_decl => "rule declaration",
            GrammarRule::source_file => "YARA rules",
            GrammarRule::string_ident => "string identifier",
            GrammarRule::string_lit => "string literal",
            GrammarRule::regexp => "regular expression",
            GrammarRule::string_mods => "string modifiers",

            GrammarRule::PERCENT => "percent `%`",
            GrammarRule::MINUS => "`-`",
            GrammarRule::COLON => "colon `:`",

            GrammarRule::ADD
            | GrammarRule::k_AND
            | GrammarRule::k_OR
            | GrammarRule::SUB
            | GrammarRule::DIV
            | GrammarRule::MUL
            | GrammarRule::MOD
            | GrammarRule::SHL
            | GrammarRule::SHR
            | GrammarRule::BITWISE_AND
            | GrammarRule::BITWISE_OR
            | GrammarRule::BITWISE_XOR
            | GrammarRule::EQ
            | GrammarRule::NEQ
            | GrammarRule::GE
            | GrammarRule::GT
            | GrammarRule::LE
            | GrammarRule::LT
            | GrammarRule::k_STARTSWITH
            | GrammarRule::k_ISTARTSWITH
            | GrammarRule::k_ENDSWITH
            | GrammarRule::k_IENDSWITH
            | GrammarRule::k_IEQUALS
            | GrammarRule::k_CONTAINS
            | GrammarRule::k_ICONTAINS
            | GrammarRule::k_MATCHES => "operator",

            GrammarRule::PIPE => "pipe `|`",
            GrammarRule::COMMA => "comma `,`",
            GrammarRule::DOT => "dot `.`",
            GrammarRule::EQUAL => "equal `=` ",

            GrammarRule::LPAREN => "opening parenthesis `(`",
            GrammarRule::RPAREN => "closing parenthesis `)`",
            GrammarRule::LBRACE => "opening brace `{`",
            GrammarRule::RBRACE => "closing brace `}`",
            GrammarRule::LBRACKET => "opening bracket `[`",
            GrammarRule::RBRACKET => "closing bracket `]`",
            GrammarRule::EOI => "end of file",

            _ => unreachable!("case `{:?}` is not handled", rule),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.report)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub(crate) struct ErrorBuilder {
    colorize_errors: bool,
    cache: HashMap<String, ariadne::Source>,
}

impl ariadne::Cache<String> for ErrorBuilder {
    fn fetch(&mut self, id: &String) -> Result<&Source, Box<dyn Debug + '_>> {
        self.cache
            .get(id)
            .ok_or(Box::new(format!("Failed to fetch source `{}`", id)) as _)
    }

    fn display<'a>(&self, id: &'a String) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(id))
    }
}

impl ErrorBuilder {
    pub(crate) fn new() -> Self {
        Self { colorize_errors: false, cache: HashMap::new() }
    }

    pub(crate) fn colorize_errors(&mut self, b: bool) -> &mut Self {
        self.colorize_errors = b;
        self
    }

    pub(crate) fn register_source(&mut self, src: &SourceCode) -> &mut Self {
        let origin = src.origin.clone().unwrap_or_else(|| "line".to_string());
        self.cache.insert(origin, ariadne::Source::from(src.text));
        self
    }

    pub(crate) fn create_report<T, L, N>(
        &mut self,
        src: &SourceCode,
        span: Span,
        title: T,
        labels: Vec<(Span, L, Style)>,
        note: Option<N>,
    ) -> Error
    where
        T: ToString,
        L: ToString,
        N: ToString,
    {
        let id = src.origin.clone().unwrap_or_else(|| "line".to_string());

        let title = if self.colorize_errors {
            Color::Default.style().bold().paint(title.to_string())
        } else {
            Color::Unset.paint(title.to_string())
        };

        let mut report_builder =
            ariadne::Report::build(self.kind_error(), id.clone(), span.start)
                .with_config(
                    ariadne::Config::default()
                        .with_color(self.colorize_errors),
                )
                .with_message(title);

        for (span, label, style) in labels {
            let label = if self.colorize_errors {
                style.paint(label.to_string())
            } else {
                Color::Unset.paint(label.to_string())
            };
            report_builder = report_builder.with_label(
                Label::new((
                    id.clone(),
                    Range { start: span.start, end: span.end },
                ))
                .with_message(label),
            );
        }

        if let Some(note) = note {
            report_builder = report_builder.with_note(note);
        }

        let report = report_builder.finish();
        let mut buffer = Vec::<u8>::new();

        report.write(self, &mut buffer).unwrap();

        Error { report: String::from_utf8(buffer).unwrap() }
    }

    pub(crate) fn simple_error_with_note<T, L, N>(
        &mut self,
        src: &SourceCode,
        span: Span,
        title: T,
        label: L,
        note: Option<N>,
    ) -> Error
    where
        T: ToString,
        L: ToString,
        N: ToString,
    {
        self.create_report(
            src,
            span,
            title,
            vec![(span, label, Color::Red.style().bold())],
            note,
        )
    }

    pub(crate) fn simple_error<T, L>(
        &mut self,
        src: &SourceCode,
        span: Span,
        title: T,
        label: L,
    ) -> Error
    where
        T: ToString,
        L: ToString,
    {
        self.simple_error_with_note(src, span, title, label, None::<T>)
    }

    pub(crate) fn duplicate_tag<T>(
        &mut self,
        src: &SourceCode,
        title: T,
        span: Span,
    ) -> Error
    where
        T: ToString,
    {
        self.simple_error(src, span, title, "duplicate tag")
    }

    pub(crate) fn duplicate_string_modifier(
        &mut self,
        src: &SourceCode,
        span: Span,
    ) -> Error {
        self.simple_error(
            src,
            span,
            "duplicate string modifier",
            "duplicate modifier",
        )
    }

    pub(crate) fn invalid_range<L>(
        &mut self,
        src: &SourceCode,
        span: Span,
        label: L,
    ) -> Error
    where
        L: ToString,
    {
        self.simple_error(src, span, "invalid range", label)
    }

    pub(crate) fn invalid_escape_sequence<L>(
        &mut self,
        src: &SourceCode,
        span: Span,
        label: L,
    ) -> Error
    where
        L: ToString,
    {
        self.simple_error(src, span, "invalid escape sequence", label)
    }

    pub(crate) fn duplicate_identifier<T>(
        &mut self,
        src: &SourceCode,
        kind: T,
        orig: &Ident,
        dup: &Ident,
    ) -> Error
    where
        T: ToString,
    {
        self.create_report(
            src,
            dup.span,
            format!(r#"duplicate {} `{}`"#, kind.to_string(), dup.name),
            vec![
                (
                    orig.span,
                    format!(
                        "`{}` declared here for the first time",
                        orig.name
                    ),
                    Color::Cyan.style().bold(),
                ),
                (
                    dup.span,
                    format!("duplicate declaration of `{}`", dup.name,),
                    Color::Red.style().bold(),
                ),
            ],
            None::<T>,
        )
    }

    pub(crate) fn convert_pest_error(
        &mut self,
        src: &SourceCode,
        pest_error: pest::error::Error<GrammarRule>,
    ) -> Error {
        // Start and ending offset within the original code that is going
        // to be highlighted in the error message. The span can cover
        // multiple lines.
        let error_span = match pest_error.location {
            InputLocation::Pos(p) => Span { start: p, end: p },
            InputLocation::Span(span) => Span { start: span.0, end: span.1 },
        };

        let label = match &pest_error.variant {
            CustomError { message } => message.to_owned(),
            ParsingError { positives, negatives } => {
                Error::syntax_error_message(
                    positives,
                    negatives,
                    Error::printable_string,
                )
            }
        };

        self.simple_error(src, error_span, "syntax error", label)
    }

    fn color(&self, c: Color) -> Color {
        if self.colorize_errors {
            c
        } else {
            Color::Unset
        }
    }

    fn kind_error(&self) -> ReportKind {
        ReportKind::Custom("error", self.color(Color::Red))
    }
}
