use std::str::from_utf8;

use regex::bytes::Regex;

use yara_x_parser::cst::{CSTStream, Event, SyntaxKind};
use yara_x_parser::Span;

/// This type hooks into a stream of [`cst::Event`] and invokes a callback for
/// each comment that suppresses a warning.
///
/// YARA users can suppress specific warnings by adding specially formatted
/// comments in rules' code. For example:
///
/// ```text
/// // suppress: text_as_hex
/// rule dummy {
///   ...
/// }
/// ```
///
/// In the example above, the `text_as_hex` warning will be suppressed for the
/// entire `dummy` rule. Similarly, in the following example, the `invariant_expr`
/// warning will be suppressed for the expression `true`:
///
/// ```text
/// rule dummy {
///   condition:
///      // suppress: invariant_expr
///      true
/// }
/// ```
///
/// The purpose of [`WarningSuppressionHook`] is to detect these suppression
/// comments and call a user-provided function with the corresponding warning
/// identifier and the span of code where the suppression applies. This mechanism
/// allows determining whether a warning should be emitted.
///
pub(crate) struct WarningSuppressionHook<'src, I, F>
where
    I: Iterator<Item = Event>,
    F: FnMut(&'src str, Span),
{
    /// Input stream.
    cst_stream: CSTStream<'src, I>,
    /// Hook function.
    f: Option<F>,
    /// Regex used for finding warning suppression comments.
    suppress_re: Regex,
    /// The starting and ending offsets of the line of code being processed.
    /// This is set to `None` after every line break.
    line_span: Option<Span>,
    /// Comments already seen in the stream of CST events that may not a have
    /// a code span assigned yet.
    pending_comments: Vec<PendingComment<'src>>,
}

#[derive(Debug)]
struct PendingComment<'src> {
    /// Comment's text.
    text: &'src [u8],
    /// Span of code that the comment refers to.
    code_span: Option<Span>,
}

impl<'src, I, F> WarningSuppressionHook<'src, I, F>
where
    I: Iterator<Item = Event>,
    F: FnMut(&'src str, Span),
{
    /// Sets the hook function to `f`.
    ///
    /// The function receives two arguments, the warning identifier and the
    /// span of code for which the warning must be suppressed.
    pub fn hook(mut self, f: F) -> Self {
        self.f = Some(f);
        self
    }
}

impl<'src, I, F, C> From<C> for WarningSuppressionHook<'src, I, F>
where
    C: Into<CSTStream<'src, I>>,
    I: Iterator<Item = Event>,
    F: FnMut(&'src str, Span),
{
    fn from(cst_events: C) -> Self {
        Self {
            f: None,
            line_span: None,
            cst_stream: cst_events.into(),
            suppress_re: Regex::new(r"suppress: (\w+)").unwrap(),
            pending_comments: vec![],
        }
    }
}

impl<'src, I, F> Iterator for WarningSuppressionHook<'src, I, F>
where
    I: Iterator<Item = Event>,
    F: FnMut(&'src str, Span),
{
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        let event = self.cst_stream.next()?;

        match event {
            Event::Token { kind: SyntaxKind::WHITESPACE, .. } => {
                // do nothing
            }
            Event::Token { kind: SyntaxKind::NEWLINE, .. }
            | Event::End { kind: SyntaxKind::SOURCE_FILE, .. } => {
                self.pending_comments.retain_mut(|comment| {
                    if comment.code_span.is_none() {
                        comment.code_span = self.line_span.clone();
                    }
                    if let Some(code_span) = &comment.code_span {
                        if let Some(hook) = &mut self.f {
                            if let Some(warning_id) = self
                                .suppress_re
                                .captures(comment.text)
                                .and_then(|captures| captures.get(1))
                                .map(|m| m.as_bytes())
                                .and_then(|m| from_utf8(m).ok())
                            {
                                hook(warning_id, code_span.clone());
                            }
                        }
                    }
                    comment.code_span.is_none()
                });
                self.line_span = None;
            }
            Event::Token { kind: SyntaxKind::COMMENT, ref span } => {
                self.pending_comments.push(PendingComment {
                    text: self.cst_stream.source().get(span.range()).unwrap(),
                    code_span: self.line_span.clone(),
                });
            }
            Event::Token { ref span, .. } => {
                if let Some(current_span) = &mut self.line_span {
                    self.line_span = Some(current_span.combine(span));
                } else {
                    self.line_span = Some(span.clone())
                };
            }
            Event::Begin { kind, ref span }
                if kind == SyntaxKind::RULE_DECL
                    || kind == SyntaxKind::PATTERN_DEF =>
            {
                for comment in self.pending_comments.iter_mut() {
                    comment.code_span = Some(span.clone());
                }
            }
            _ => {}
        }

        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use yara_x_parser::cst::Event;
    use yara_x_parser::{Parser, Span};

    use crate::compiler::wsh::WarningSuppressionHook;

    #[test]
    fn warning_suppression() {
        let parser = Parser::new(
            b"
// suppress: foo
rule test { // suppress: bar
    // suppress: baz
    condition: true
}
        ",
        );

        let mut map: HashMap<&str, Vec<Span>> = HashMap::new();

        let cst =
            WarningSuppressionHook::from(parser).hook(|warning, span| {
                map.entry(warning).or_default().push(span);
            });

        let _ = cst.collect::<Vec<Event>>();

        let expected: HashMap<_, _> = vec![
            // foo is suppressed for the whole rule
            ("foo", vec![Span(18..89)]),
            // bar is suppressed for "rule test {"
            ("bar", vec![Span(18..29)]),
            // baz is suppressed for "condition: true"
            ("baz", vec![Span(72..87)]),
        ]
        .into_iter()
        .collect();

        assert_eq!(map, expected);
    }
}
