use annotate_snippets::renderer;
use annotate_snippets::renderer::{AnsiColor, Color, DEFAULT_TERM_WIDTH};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
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
/// This structure represents the message displayed to the user when an error
/// or warning occurs. It implements the [`Display`] trait, ensuring that when
/// printed, it reflects the standard error format used by YARA-X. For example:
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
/// In addition to generating the report, this type provides access to the
/// individual components of the report, which include:
///
/// - `level`: Indicates the severity, either `Level::Error` or `Level::Warning`.
/// - `code`: A unique code that identifies the specific error or warning
///           (e.g., "E006").
/// - `title`: The title of the report (e.g., "unexpected negative number").
/// - `labels`: A collection of labels included in the report. Each label
///             contains a level, a span, and associated text.
/// - `footers`: A collection notes that appear after the end of the report.
#[derive(Clone)]
pub(crate) struct Report {
    code_cache: Arc<CodeCache>,
    default_source_id: SourceId,
    with_colors: bool,
    max_with: usize,
    level: Level,
    code: &'static str,
    title: String,
    labels: Vec<(Level, CodeLoc, String)>,
    footers: Vec<(Level, String)>,
}

impl Report {
    /// Returns the report's title.
    #[inline]
    pub(crate) fn title(&self) -> &str {
        self.title.as_str()
    }

    /// Returns the report's labels.
    pub(crate) fn labels(&self) -> impl Iterator<Item = Label> {
        self.labels.iter().map(|(level, code_loc, text)| {
            let source_id =
                code_loc.source_id.unwrap_or(self.default_source_id);

            let code_cache = self.code_cache.read();
            let cache_entry = code_cache.get(&source_id).unwrap();
            let code_origin = cache_entry.origin.clone();

            // This could be faster if we maintain an ordered vector with the
            // byte offset where each line begins. By doing a binary search
            // on that vector, we can locate the line number in O(log(N))
            // instead of O(N).
            let (line, column) = byte_offset_to_line_col(
                &cache_entry.code,
                code_loc.span.start(),
            )
            .unwrap();

            Label {
                level: level_as_text(*level),
                code_origin,
                line,
                column,
                span: code_loc.span.clone(),
                text,
            }
        })
    }

    /// Returns the report's footers.
    #[inline]
    pub(crate) fn footers(&self) -> impl Iterator<Item = Footer> {
        self.footers
            .iter()
            .map(|(level, text)| Footer { level: level_as_text(*level), text })
    }
}

impl Serialize for Report {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let labels = self.labels().collect::<Vec<_>>();
        let footers = &self.footers().collect::<Vec<_>>();

        let mut s = serializer.serialize_struct("report", 4)?;

        s.serialize_field("code", &self.code)?;
        s.serialize_field("title", &self.title)?;

        // Find the first label with the same level as the report itself.
        // The report's line and column will be the line and column of
        // that label.
        if let Some(label) = labels
            .iter()
            .find(|label| label.level == level_as_text(self.level))
        {
            s.serialize_field("line", &label.line)?;
            s.serialize_field("column", &label.column)?;
        }

        s.serialize_field("labels", &labels)?;
        s.serialize_field("footers", &footers)?;
        s.serialize_field("text", &self.to_string())?;
        s.end()
    }
}

impl PartialEq for Report {
    fn eq(&self, other: &Self) -> bool {
        self.level.eq(&other.level)
            && self.code.eq(other.code)
            && self.title.eq(&other.title)
            && self.labels.eq(&other.labels)
            && self.footers.eq(&other.footers)
    }
}

impl Eq for Report {}

impl Debug for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Use the SourceId indicated by the first label, or the one
        // corresponding to the current source file (i.e: the most
        // recently registered).
        let source_id = self
            .labels
            .first()
            .and_then(|label| label.1.source_id)
            .unwrap_or(self.default_source_id);

        let code_cache = self.code_cache.read();
        let mut cache_entry = code_cache.get(&source_id).unwrap();
        let mut src = cache_entry.code.as_str();

        let mut message = self.level.title(self.title.as_str()).id(self.code);
        let mut snippet = annotate_snippets::Snippet::source(src)
            .origin(cache_entry.origin.as_deref().unwrap_or("line"))
            .fold(true);

        for (level, label_ref, label) in &self.labels {
            let label_source_id =
                label_ref.source_id.unwrap_or(self.default_source_id);

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

        for (level, text) in &self.footers {
            message = message.footer(level.title(text.as_str()));
        }

        let renderer = if self.with_colors {
            annotate_snippets::Renderer::styled()
        } else {
            annotate_snippets::Renderer::plain()
        };

        let renderer = renderer.term_width(self.max_with);
        let text = renderer.render(message);

        write!(f, "{}", text)
    }
}

/// Represents a label in an error or warning report.
#[derive(Serialize)]
pub struct Label<'a> {
    level: &'a str,
    code_origin: Option<String>,
    line: usize,
    column: usize,
    span: Span,
    text: &'a str,
}

/// Represents a footer in an error or warning report.
#[derive(Serialize)]
pub struct Footer<'a> {
    level: &'a str,
    text: &'a str,
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
    max_with: usize,
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
            max_with: DEFAULT_TERM_WIDTH,
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

    /// Sets the maximum number of columns while rendering error messages.
    ///
    /// The default value is 140.
    pub fn max_with(&mut self, with: usize) -> &mut Self {
        self.max_with = with;
        self
    }

    /// Returns the [`SourceId`] for the most recently registered source file.
    pub fn current_source_id(&self) -> Option<SourceId> {
        self.current_source_id.get()
    }

    /// Returns the green style used in error/warning reports.
    ///
    /// This is an example of how to use it:
    ///
    /// ```text
    /// let style = report_builder.green_style();
    /// format!("lorem ipsum {style}dolor sit amet{style:#}");
    /// ```
    ///
    /// In the example above "dolor sit amet" will be painted in green, except
    /// if colors are disabled.
    pub fn green_style(&self) -> renderer::Style {
        if self.with_colors {
            renderer::Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightGreen)))
        } else {
            renderer::Style::new()
        }
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

        src[source_ref.span().range()].to_string()
    }

    /// Creates a new error or warning report.
    pub fn create_report(
        &self,
        level: Level,
        code: &'static str,
        title: String,
        labels: Vec<(Level, CodeLoc, String)>,
        footers: Vec<(Level, Option<String>)>,
    ) -> Report {
        // Make sure there's at least one label.
        assert!(!labels.is_empty());

        // Remove footers where text is None.
        let footers = footers
            .into_iter()
            .filter_map(|(level, text)| text.map(|text| (level, text)))
            .collect();

        Report {
            code_cache: self.code_cache.clone(),
            with_colors: self.with_colors,
            max_with: self.max_with,
            default_source_id: self.current_source_id().expect(
                "`create_report` called without registering any source",
            ),
            level,
            code,
            title,
            labels,
            footers,
        }
    }
}

fn level_as_text(level: Level) -> &'static str {
    match level {
        Level::Error => "error",
        Level::Warning => "warning",
        Level::Info => "info",
        Level::Note => "note",
        Level::Help => "help",
    }
}

/// Given a text slice and a position indicated as a byte offset, returns
/// the same position as a (line, column) pair.
fn byte_offset_to_line_col(
    text: &str,
    byte_offset: usize,
) -> Option<(usize, usize)> {
    // Check if the byte_offset is valid
    if byte_offset > text.len() {
        return None; // Out of bounds
    }

    let mut line = 1;
    let mut col = 1;

    // Iterate through the characters (not bytes) in the string
    for (i, c) in text.char_indices() {
        if i == byte_offset {
            return Some((line, col));
        }
        if c == '\n' {
            line += 1;
            col = 1; // Reset column to 1 after a newline
        } else {
            col += 1;
        }
    }

    // If the byte_offset points to the last byte of the string, return the final position
    if byte_offset == text.len() {
        return Some((line, col));
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::compiler::report::byte_offset_to_line_col;

    #[test]
    fn byte_offset_to_line_col_single_line() {
        let text = "Hello, World!";
        assert_eq!(byte_offset_to_line_col(text, 0), Some((1, 1))); // Start of the string
        assert_eq!(byte_offset_to_line_col(text, 7), Some((1, 8))); // Byte offset of 'W'
        assert_eq!(byte_offset_to_line_col(text, 12), Some((1, 13))); // Byte offset of '!'
    }

    #[test]
    fn byte_offset_to_line_col_multiline() {
        let text = "Hello\nRust\nWorld!";
        assert_eq!(byte_offset_to_line_col(text, 0), Some((1, 1))); // First character
        assert_eq!(byte_offset_to_line_col(text, 5), Some((1, 6))); // End of first line (newline)
        assert_eq!(byte_offset_to_line_col(text, 6), Some((2, 1))); // Start of second line ('R')
        assert_eq!(byte_offset_to_line_col(text, 9), Some((2, 4))); // Byte offset of 't' in "Rust"
        assert_eq!(byte_offset_to_line_col(text, 11), Some((3, 1))); // Start of third line ('W')
    }

    #[test]
    fn byte_offset_to_line_col_empty_string() {
        let text = "";
        assert_eq!(byte_offset_to_line_col(text, 0), Some((1, 1)));
    }

    #[test]
    fn byte_offset_to_line_col_out_of_bounds() {
        let text = "Hello, World!";
        assert_eq!(byte_offset_to_line_col(text, text.len() + 1), None);
    }

    #[test]
    fn byte_offset_to_line_col_end_of_string() {
        let text = "Hello, World!";
        assert_eq!(byte_offset_to_line_col(text, text.len()), Some((1, 14))); // Last position after '!'
    }

    #[test]
    fn byte_offset_to_line_col_multibyte_characters() {
        let text = "Hello, 你好!";
        assert_eq!(byte_offset_to_line_col(text, 7), Some((1, 8))); // Position of '你'
        assert_eq!(byte_offset_to_line_col(text, 10), Some((1, 9))); // Position of '好'
        assert_eq!(byte_offset_to_line_col(text, 13), Some((1, 10))); // Position of '!'
    }
}
