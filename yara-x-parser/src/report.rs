use std::borrow::Cow;
use std::cell::RefCell;
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

/// Build error and warning reports.
pub struct ReportBuilder {
    with_colors: bool,
    // RefCell allows getting a mutable reference to the cache, even if we have
    // an immutable reference to the report builder.
    cache: RefCell<Cache>,
}

struct Cache {
    data: CacheMap,
}

struct CacheMap(HashMap<String, ariadne::Source>);

/// &CacheMap implements the [`ariadne::Cache`] trait.
impl ariadne::Cache<String> for &CacheMap {
    fn fetch(&mut self, id: &String) -> Result<&Source, Box<dyn Debug + '_>> {
        self.0
            .get(id)
            .ok_or(Box::new(format!("Failed to fetch source `{}`", id)) as _)
    }

    fn display<'a>(&self, id: &'a String) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(id))
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
            cache: RefCell::new(Cache { data: CacheMap(HashMap::new()) }),
        }
    }

    /// Indicates whether the reports should have colors. By default this is
    /// `false`.
    pub fn with_colors(&mut self, b: bool) -> &mut Self {
        self.with_colors = b;
        self
    }

    /// Registers a source code with the report builder.
    ///
    /// Before calling [`ReportBuilder::create_report`] with some [`SourceCode`]
    /// the source code must be registered by calling this function. If
    /// [`SourceCode`] was already registered this is a no-op.
    ///
    /// This function allows code that is not valid UTF-8, in such cases it
    /// replaces the invalid characters with the UTF-8 replacement character.
    pub(crate) fn register_source(&self, src: &SourceCode) -> &Self {
        let key = src.origin.as_deref().unwrap_or("line");
        {
            let map = &mut self.cache.borrow_mut().data.0;
            // ariadne::Source::from(...) is an expensive operation, so it's
            // done only if the SourceCode is not already in the cache.
            if map.get(key).is_none() {
                let s = if let Some(s) = src.valid {
                    Cow::Borrowed(s)
                } else {
                    String::from_utf8_lossy(src.raw.as_ref())
                };
                map.insert(key.to_string(), ariadne::Source::from(s));
            }
        }
        self
    }

    /// Creates a new error or warning report.
    pub fn create_report(
        &self,
        report_type: ReportType,
        src: &SourceCode,
        span: Span,
        title: String,
        labels: Vec<(Span, String, Style)>,
        note: Option<String>,
    ) -> String {
        let id = src.origin.clone().unwrap_or_else(|| "line".to_string());

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
            ariadne::Report::build(kind, id.clone(), span.start)
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

        report.write(&self.cache.borrow_mut().data, &mut buffer).unwrap();

        String::from_utf8(buffer).unwrap()
    }

    pub(crate) fn convert_pest_error(
        &self,
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
            src,
            error_span,
            "syntax error".to_string(),
            vec![(error_span, error_msg.clone(), Color::Red.style().bold())],
            None,
        );

        Error::new(ErrorInfo::SyntaxError {
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
