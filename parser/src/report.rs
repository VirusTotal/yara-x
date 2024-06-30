use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt::Debug;

use annotate_snippets;
use pest::error::ErrorVariant::{CustomError, ParsingError};
use pest::error::InputLocation;

use crate::ast::Span;
use crate::parser::GrammarRule;
use crate::parser::SourceCode;
use crate::parser::{Error, ErrorInfo};

pub type Level = annotate_snippets::Level;

/// Identifier associated to each source file registered in a [`ReportBuilder`].
///
/// Each source file gets its own unique `SourceId` when it is registered
/// via [register_source]. These identifiers are stored in [`Span`] instances
/// all over the `AST`, indicating the original source file that contained the
/// span. When some [`Span`] is passed to [create_report], the report builder
/// can use the [`SourceId`] for locating the original source file and extract
/// the corresponding code snippet from it.
///
/// [register_source]: ReportBuilder::register_source
/// [create_report]: ReportBuilder::create_report
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug, Default)]
pub struct SourceId(u32);

/// Builds error and warning reports.
///
/// `ReportBuilder` helps to create error and warning reports. It stores a copy
/// of every source file registered with [register_source], and then allows
/// creating error reports with annotated code snippets obtained from those
/// source files.
///
/// [register_source]: ReportBuilder::register_source
pub struct ReportBuilder {
    with_colors: bool,
    current_source_id: Cell<Option<SourceId>>,
    next_source_id: Cell<SourceId>,
    // RefCell allows getting a mutable reference to the cache, even if we have
    // an immutable reference to the report builder.
    cache: RefCell<Cache>,
}

/// A cache containing source files registered in a [`ReportBuilder`].
struct Cache {
    data: HashMap<SourceId, CacheEntry>,
}

/// Each of the entries stored in [`Cache`].
struct CacheEntry {
    code: String,
    origin: Option<String>,
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportBuilder {
    /// Creates a new instance of [`ReportBuilder`].
    pub fn new() -> Self {
        Self {
            with_colors: false,
            current_source_id: Cell::new(None),
            next_source_id: Cell::new(SourceId(0)),
            cache: RefCell::new(Cache { data: HashMap::new() }),
        }
    }

    /// Indicates whether the reports should have colors. By default, this is
    /// `false`.
    pub fn with_colors(&mut self, yes: bool) -> &mut Self {
        self.with_colors = yes;
        self
    }

    /// Returns the [`SourceId`] for the most recently registered source file.
    pub(crate) fn current_source_id(&self) -> Option<SourceId> {
        self.current_source_id.get()
    }

    /// Registers a source code with the report builder.
    ///
    /// Before calling [`ReportBuilder::create_report`] with some [`SourceCode`]
    /// the source code must be registered by calling this function. If
    /// [`SourceCode`] was already registered this is a no-op.
    ///
    /// This function allows code that is not valid UTF-8, in such cases it
    /// replaces the invalid characters with the UTF-8 replacement character.
    pub fn register_source(&self, src: &SourceCode) -> &Self {
        let source_id = self.next_source_id.get();
        self.next_source_id.set(SourceId(source_id.0 + 1));
        self.current_source_id.set(Some(source_id));

        let map = &mut self.cache.borrow_mut().data;
        map.entry(source_id).or_insert_with(|| {
            let s = if let Some(s) = src.valid {
                Cow::Borrowed(s)
            } else {
                String::from_utf8_lossy(src.raw.as_ref())
            };
            CacheEntry {
                // Replace tab characters with a single space. This doesn't affect
                // code spans, because the number of characters remain the same,
                // but prevents error messages from being wrongly formatted
                //  when they are printed.
                code: s.replace('\t', " "),
                origin: src.origin.clone(),
            }
        });
        self
    }

    /// Creates a new error or warning report.
    pub fn create_report(
        &self,
        level: Level,
        span: Span,
        code: &str,
        title: &str,
        labels: Vec<(Span, String, Level)>,
        note: Option<String>,
    ) -> String {
        let cache = self.cache.borrow();
        let mut source_id = span.source_id();
        let mut cache_entry = cache.data.get(&source_id).unwrap();
        let mut src = cache_entry.code.as_str();

        let mut message = level.title(title).id(code);

        let mut snippet = annotate_snippets::Snippet::source(src)
            .origin(cache_entry.origin.as_deref().unwrap_or("line"))
            .fold(true);

        for (span, label, level) in &labels {
            if span.source_id() == source_id {
                snippet = snippet.annotation(
                    level.span(span.start()..span.end()).label(label.as_str()),
                );
            } else {
                source_id = span.source_id();
                message = message.snippet(snippet);
                cache_entry = cache.data.get(&source_id).unwrap();
                src = cache_entry.code.as_str();
                snippet = annotate_snippets::Snippet::source(src)
                    .origin(cache_entry.origin.as_deref().unwrap_or("line"))
                    .fold(true)
                    .annotation(
                        level
                            .span(span.start()..span.end())
                            .label(label.as_str()),
                    )
            }
        }

        message = message.snippet(snippet);

        if let Some(note) = &note {
            message = message.footer(Level::Note.title(note.as_str()));
        }

        let renderer = if self.with_colors {
            annotate_snippets::Renderer::styled()
        } else {
            annotate_snippets::Renderer::plain()
        };

        let message = renderer.render(message);

        message.to_string()
    }

    pub(crate) fn convert_pest_error(
        &self,
        pest_error: pest::error::Error<GrammarRule>,
    ) -> Error {
        // Start and ending offset within the original code that is going
        // to be highlighted in the error message. The span can cover
        // multiple lines.
        let error_span = match pest_error.location {
            InputLocation::Pos(p) => {
                Span::new(self.current_source_id.get().unwrap(), p, p)
            }
            InputLocation::Span(span) => Span::new(
                self.current_source_id.get().unwrap(),
                span.0,
                span.1,
            ),
        };

        let (title, error_msg, note) = match &pest_error.variant {
            CustomError { message } => {
                // 'call limit reached' is the error message returned by Pest
                // when it reaches the limit set with pest::set_call_limit.
                // This error message is not useful for final users, here we
                // replace the message and provide more information.
                if message == "call limit reached" {
                    (
                        "code is too complex or large",
                        "parser aborted here".to_owned(),
                        Some(
                            "reduce the number of nested parenthesis or the \
                            size of your source code "
                                .to_owned(),
                        ),
                    )
                } else {
                    ("syntax error", message.to_owned(), None)
                }
            }
            ParsingError { positives, negatives } => (
                "syntax error",
                ErrorInfo::syntax_error_message(
                    positives,
                    negatives,
                    ErrorInfo::printable_string,
                ),
                None,
            ),
        };

        let detailed_report = self.create_report(
            Level::Error,
            error_span,
            "E001",
            title,
            vec![(error_span, error_msg.clone(), Level::Error)],
            note,
        );

        Error::from(ErrorInfo::SyntaxError {
            detailed_report,
            error_msg,
            error_span,
        })
    }
}
