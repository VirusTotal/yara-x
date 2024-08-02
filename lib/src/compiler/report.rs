use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt::Debug;

use yara_x_parser::Span;

use crate::SourceCode;

pub type Level = annotate_snippets::Level;

/// Identifier for each source code file registered in a [`ReportBuilder`].
/// Each source file gets assigned its own unique `SourceId` when registered
/// via [`ReportBuilder::register_source`].
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug, Default)]
pub struct SourceId(u32);

/// A `SourceRef` points to a fragment of source code.
///
/// It consists of a [`SourceId`] and a [`Span`], where the former identifies
/// the source file, and the latter a span of text within that source file.
///
/// The [`SourceId`] is optional, if it is [`None`] it means that the [`Span`]
/// is relative to the current source file.
#[derive(PartialEq, Clone, Eq, Default)]
pub struct SourceRef {
    source_id: Option<SourceId>,
    span: Span,
}

impl SourceRef {
    pub(crate) fn new(source_id: Option<SourceId>, span: Span) -> Self {
        Self { source_id, span }
    }
}

impl From<&Span> for SourceRef {
    /// Creates a [`SourceRef`] from a reference to a [`Span`].
    fn from(span: &Span) -> Self {
        Self { source_id: None, span: span.clone() }
    }
}

impl From<Span> for SourceRef {
    /// Creates a [`SourceRef`] from a [`Span`].
    fn from(span: Span) -> Self {
        Self { source_id: None, span }
    }
}

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
    /// Before calling [`ReportBuilder::create_report`] for creating error
    /// reports, the source code containing the error must be registered
    /// using this function. If it was already registered this is a no-op.
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
                // Replace tab characters with a single space. This doesn't
                // affect code spans, because the number of characters remain
                // the same, but prevents error messages from being wrongly
                // formatted when they are printed.
                code: s.replace('\t', " "),
                origin: src.origin.clone(),
            }
        });
        self
    }

    /// Returns the fragment of source code indicated by `source_ref`.
    pub fn get_snippet(&self, source_ref: &SourceRef) -> String {
        let source_id = source_ref
            .source_id
            .or_else(|| self.current_source_id())
            .expect("create_report without registering any source code");

        let cache = self.cache.borrow();
        let cache_entry = cache.data.get(&source_id).unwrap();
        let src = cache_entry.code.as_str();

        src[source_ref.span.range()].to_string()
    }

    /// Creates a new error or warning report.
    pub fn create_report(
        &self,
        level: Level,
        source_ref: &SourceRef,
        code: &str,
        title: &str,
        labels: Vec<(&SourceRef, String, Level)>,
        note: Option<String>,
    ) -> String {
        // Use the SourceId indicated in the SourceRef, or SourceId
        // corresponding to the current source file (i.e: the most
        // recently registered).
        let source_id = source_ref
            .source_id
            .or_else(|| self.current_source_id())
            .expect("create_report without registering any source code");

        let cache = self.cache.borrow();
        let mut cache_entry = cache.data.get(&source_id).unwrap();
        let mut src = cache_entry.code.as_str();

        let mut message = level.title(title).id(code);
        let mut snippet = annotate_snippets::Snippet::source(src)
            .origin(cache_entry.origin.as_deref().unwrap_or("line"))
            .fold(true);

        for (label_ref, label, level) in &labels {
            let label_source_id = label_ref
                .source_id
                .or_else(|| self.current_source_id())
                .unwrap();

            // If the current label doesn't belong to the same source file
            // finish the current snippet, add it to the error message and
            // start a new snippet for the label's source file.
            if label_source_id != source_id {
                cache_entry = cache.data.get(&label_source_id).unwrap();
                src = cache_entry.code.as_str();
                message = message.snippet(snippet);
                snippet = annotate_snippets::Snippet::source(src)
                    .origin(cache_entry.origin.as_deref().unwrap_or("line"))
                    .fold(true)
            }

            let span_start = label_ref.span.start();
            let span_end = label_ref.span.end();

            snippet = snippet.annotation(
                level.span(span_start..span_end).label(label.as_str()),
            );
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
}
