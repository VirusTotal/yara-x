use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use yara_x_parser::Span;

use crate::SourceCode;

pub type Level = annotate_snippets::Level;

/// Identifier for each source code file registered in a [`ReportBuilder`].
/// Each source file gets assigned its own unique `SourceId` when registered
/// via [`ReportBuilder::register_source`].
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug, Default)]
pub struct SourceId(u32);

/// A `CodeLoc` points to a fragment of source code.
///
/// It consists of a [`SourceId`] and a [`Span`], where the former identifies
/// the source file, and the latter a span of text within that source file.
///
/// The [`SourceId`] is optional, if it is [`None`] it means that the [`Span`]
/// is relative to the current source file.
#[derive(PartialEq, Debug, Clone, Eq, Default)]
pub struct CodeLoc {
    source_id: Option<SourceId>,
    span: Span,
}

impl CodeLoc {
    pub(crate) fn new(source_id: Option<SourceId>, span: Span) -> Self {
        Self { source_id, span }
    }

    /// Returns the span within the source code.
    #[inline]
    pub fn span(&self) -> &Span {
        &self.span
    }
}

impl From<&Span> for CodeLoc {
    /// Creates a [`CodeLoc`] from a reference to a [`Span`].
    fn from(span: &Span) -> Self {
        Self { source_id: None, span: span.clone() }
    }
}

impl From<Span> for CodeLoc {
    /// Creates a [`CodeLoc`] from a [`Span`].
    fn from(span: Span) -> Self {
        Self { source_id: None, span }
    }
}

/// Represents an error or warning report.
///
/// A report is the message shown to the user when some error or warning
/// occurs. This type implements the [`Display`] trait, and when printed
/// it shows the typical error message you get from YARA-X. Like this one:
///
/// ```text
/// error[E006]: unexpected negative number
///  --> line:6:12
///   |
/// 6 |     $a in (-1..0)
///   |            ^^ this number can not be negative
///   |
/// ```
///
/// Besides printing the report, this type give access to each of the
/// components of the report.
pub struct Report {
    text: String,
    code_cache: Arc<CodeCache>,
}

impl PartialEq for Report {
    fn eq(&self, other: &Self) -> bool {
        self.text.eq(&other.text)
    }
}

impl Eq for Report {}

impl Debug for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.text)
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
    code_cache: Arc<CodeCache>,
}

/// A cache containing source files registered in a [`ReportBuilder`].
struct CodeCache {
    data: RwLock<HashMap<SourceId, CodeCacheEntry>>,
}

impl CodeCache {
    fn new() -> Self {
        Self { data: RwLock::new(HashMap::new()) }
    }

    pub fn read(
        &self,
    ) -> RwLockReadGuard<'_, HashMap<SourceId, CodeCacheEntry>> {
        self.data.read().unwrap()
    }

    pub fn write(
        &self,
    ) -> RwLockWriteGuard<'_, HashMap<SourceId, CodeCacheEntry>> {
        self.data.write().unwrap()
    }
}

/// Each of the entries stored in [`CodeCache`].
struct CodeCacheEntry {
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
            code_cache: Arc::new(CodeCache::new()),
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

        self.code_cache.write().entry(source_id).or_insert_with(|| {
            let s = if let Some(s) = src.valid {
                Cow::Borrowed(s)
            } else {
                String::from_utf8_lossy(src.raw.as_ref())
            };
            CodeCacheEntry {
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
    pub fn get_snippet(&self, source_ref: &CodeLoc) -> String {
        let source_id = source_ref
            .source_id
            .or_else(|| self.current_source_id())
            .expect("create_report without registering any source code");

        let code_cache = self.code_cache.read();
        let cache_entry = code_cache.get(&source_id).unwrap();
        let src = cache_entry.code.as_str();

        src[source_ref.span.range()].to_string()
    }

    /// Creates a new error or warning report.
    pub fn create_report(
        &self,
        level: Level,
        code: &'static str,
        title: String,
        labels: Vec<(CodeLoc, String, Level)>,
        note: Option<String>,
    ) -> Report {
        // Make sure there's at least one label.
        assert!(!labels.is_empty());

        // Use the SourceId indicated by the first label, or the one
        // corresponding to the current source file (i.e: the most
        // recently registered).
        let source_id = labels
            .first()
            .and_then(|label| label.0.source_id)
            .or_else(|| self.current_source_id())
            .expect("create_report without registering any source code");

        let code_cache = self.code_cache.read();
        let mut cache_entry = code_cache.get(&source_id).unwrap();
        let mut src = cache_entry.code.as_str();

        let mut message = level.title(title.as_str()).id(code);
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
                cache_entry = code_cache.get(&label_source_id).unwrap();
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

        Report {
            code_cache: self.code_cache.clone(),
            text: message.to_string(),
        }
    }
}
