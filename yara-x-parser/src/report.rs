use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::ops::Range;

use ariadne::{Color, Label, ReportKind, Source};
use pest::error::ErrorVariant::{CustomError, ParsingError};
use pest::error::InputLocation;
use yansi::Style;

use crate::ast::Span;
use crate::parser::GrammarRule;
use crate::parser::SourceCode;
use crate::parser::{Error, ErrorInfo};

/// Types of reports created by [`ReportBuilder`].
pub enum ReportType {
    Error,
    Warning,
}

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
/// `ReportBuilder` helps creating error and warning reports. It stores a copy
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
    /// The source code, as stored by [`ariadne`].
    source: Source,
    /// A copy of the source code. The field is used only by
    /// [`ReportBuilder::ast_span_to_ariadne`] for converting AST byte-wise
    /// spans to character-wise spans expected by [`ariadne`]. Unfortunately
    /// the `source` field above is not an exact copy of the source code
    /// (trailing spaces are removed) and therefore can't be used for this
    /// purpose. Having two copies of each source file, and making these span
    /// conversions is quite inefficient, but the alternative is adapting
    /// [`ariadne`] to our needs or switching to a similar crate that works
    /// with byte-wise spans.
    /// TODO: consider adapting ariadne to our needs by allowing byte-wise
    /// spans.
    code: String,
    origin: Option<String>,
}

/// &Cache implements the [`ariadne::Cache`] trait.
impl ariadne::Cache<SourceId> for &Cache {
    /// Called when `ariadne` needs to retrieve a source code by [`SourceId`].
    fn fetch(
        &mut self,
        id: &SourceId,
    ) -> Result<&Source, Box<dyn Debug + '_>> {
        self.data
            .get(id)
            .map(|entry| &entry.source)
            .ok_or(Box::new(format!("failed to fetch source `{:?}`", id)) as _)
    }

    /// Called when `ariadne` needs to display a string identifying a source
    /// code in the error report. For example, in the report below the string
    /// `test.yar` in `[test.yar:1:6]` is returned by this function.
    ///
    /// ```text
    /// error: some error message here
    ///    ╭─[test.yar:1:6]
    ///    .
    ///    .
    /// ───╯
    /// ```
    ///
    /// This function returns the origin associated with the source file, if
    /// any, or the placeholder `line`.
    fn display<'a>(&self, id: &'a SourceId) -> Option<Box<dyn Display + 'a>> {
        if let Some(origin) = self.data.get(id).unwrap().origin.as_ref() {
            Some(Box::new(origin.clone()))
        } else {
            Some(Box::new("line"))
        }
    }
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

    /// Indicates whether the reports should have colors. By default this is
    /// `false`.
    pub fn with_colors(&mut self, b: bool) -> &mut Self {
        self.with_colors = b;
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
        // ariadne::Source::from(...) is an expensive operation, so it's
        // done only if the SourceCode is not already in the cache.
        map.entry(source_id).or_insert_with(|| {
            let s = if let Some(s) = src.valid {
                Cow::Borrowed(s)
            } else {
                String::from_utf8_lossy(src.raw.as_ref())
            };
            CacheEntry {
                source: ariadne::Source::from(s.as_ref()),
                code: s.to_string(),
                origin: src.origin.clone(),
            }
        });
        self
    }

    /// Creates a new error or warning report.
    pub fn create_report(
        &self,
        report_type: ReportType,
        span: Span,
        title: String,
        labels: Vec<(Span, String, Style)>,
        note: Option<String>,
    ) -> String {
        let kind = match report_type {
            ReportType::Error => {
                ReportKind::Custom("error", self.color(Color::Red))
            }
            ReportType::Warning => {
                ReportKind::Custom("warning", self.color(Color::Yellow))
            }
        };

        let title = if self.with_colors {
            Color::Default.style().bold().paint(title)
        } else {
            Color::Unset.paint(title)
        };

        let source_id = span.source_id();
        // The span specified in the AST are byte-wise, but the spans expected
        // by Ariadne are character-wise. Some conversion is required.
        let span = self.ast_span_to_ariadne(span);

        let mut report_builder =
            ariadne::Report::build(kind, source_id, span.start)
                .with_config(
                    ariadne::Config::default().with_color(self.with_colors),
                )
                .with_message(title);

        for (span, label, style) in labels {
            let label = if self.with_colors {
                style.paint(label)
            } else {
                Color::Unset.paint(label)
            };

            let source_id = span.source_id();
            let span = self.ast_span_to_ariadne(span);

            report_builder = report_builder
                .with_label(Label::new((source_id, span)).with_message(label));
        }

        if let Some(note) = note {
            report_builder = report_builder.with_note(note);
        }

        let report = report_builder.finish();
        let mut buffer = Vec::<u8>::new();

        report.write(&*self.cache.borrow(), &mut buffer).unwrap();

        String::from_utf8(buffer).unwrap()
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
            ReportType::Error,
            error_span,
            title.to_string(),
            vec![(error_span, error_msg.clone(), Color::Red.style().bold())],
            note,
        );

        Error::from(ErrorInfo::SyntaxError {
            detailed_report,
            error_msg,
            error_span,
        })
    }

    /// Converts an AST [`Span`] to an ariadne span.
    ///
    /// AST spans are bytewise ranges within the source code (i.e: the
    /// `start` and `end` fields in [`Span`] are byte offsets. The
    /// [`ariadne`] crate however works with character-wise spans (they
    /// indicate the starting and ending characters within the source
    /// code).
    ///
    /// For pure ASCII source codes, where each character is represented
    /// by a single byte, this is not an issue, but UTF-8 characters are
    /// not always 1-byte long. This means that AST span must converted
    /// to character-wise spans before being passed to [`ariadne`]
    fn ast_span_to_ariadne(&self, span: Span) -> Range<usize> {
        let cache = self.cache.borrow();
        let cache_entry = cache.data.get(&span.source_id()).unwrap();
        let code = cache_entry.code.as_str();

        // `char_start` is the number of UTF-8 characters (not bytes) that are
        // from the start of the code to the start of the span.
        let char_start = code[0..span.start()].chars().count();

        // `char_end` is the number of UTF-8 characters from the start of the
        // code to the end of the span.
        let char_end =
            char_start + code[span.start()..span.end()].chars().count();

        char_start..char_end
    }

    fn color(&self, c: Color) -> Color {
        if self.with_colors {
            c
        } else {
            Color::Unset
        }
    }
}
