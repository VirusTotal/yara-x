use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt::{Debug, Display};

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
    source: Source,
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
                source: ariadne::Source::from(s),
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

        let mut report_builder =
            ariadne::Report::build(kind, span.source_id, span.start)
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
            report_builder = report_builder.with_label(
                Label::new((span.source_id, span.start..span.end))
                    .with_message(label),
            );
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
            InputLocation::Pos(p) => Span {
                source_id: self.current_source_id.get().unwrap(),
                start: p,
                end: p,
            },
            InputLocation::Span(span) => Span {
                source_id: self.current_source_id.get().unwrap(),
                start: span.0,
                end: span.1,
            },
        };

        let error_msg = match &pest_error.variant {
            CustomError { message } => message.to_owned(),
            ParsingError { positives, negatives } => {
                ErrorInfo::syntax_error_message(
                    positives,
                    negatives,
                    ErrorInfo::printable_string,
                )
            }
        };

        let detailed_report = self.create_report(
            ReportType::Error,
            error_span,
            "syntax error".to_string(),
            vec![(error_span, error_msg.clone(), Color::Red.style().bold())],
            None,
        );

        Error::from(ErrorInfo::SyntaxError {
            detailed_report,
            error_msg,
            error_span,
        })
    }

    fn color(&self, c: Color) -> Color {
        if self.with_colors {
            c
        } else {
            Color::Unset
        }
    }
}
