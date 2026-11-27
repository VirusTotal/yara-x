use std::str::from_utf8;

use regex::bytes::Regex;

use yara_x_parser::Span;
use yara_x_parser::cst::{CSTStream, Event, SyntaxKind};

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
    code_span: Option<Span>,
    /// Comments already seen in the stream of CST events that don't have a
    /// code span assigned yet. A comment is removed from this list as soon
    /// as the span of code it refers to is known, so that each comment is
    /// visited only once, regardless of how many lines without code follow
    /// it.
    pending_comments: Vec<&'src [u8]>,
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

    /// Processes `comment`, invoking `hook` for each warning suppressed by it,
    /// where `code_span` is the span of code that the comment refers to.
    fn process_comment(
        suppress_re: &Regex,
        hook: &mut F,
        comment: &'src [u8],
        code_span: &Span,
    ) {
        if let Some(captures) = suppress_re.captures(comment)
            && let Some(m) = captures.get(1)
            && let Ok(s) = from_utf8(m.as_bytes())
        {
            for warning_id in s.split(',') {
                hook(warning_id.trim(), code_span.clone());
            }
        }
    }

    /// Processes all pending comments against `code_span`, leaving the list of
    /// pending comments empty.
    fn process_pending_comments(&mut self, code_span: &Span) {
        if let Some(hook) = &mut self.f {
            for comment in self.pending_comments.drain(..) {
                Self::process_comment(
                    &self.suppress_re,
                    hook,
                    comment,
                    code_span,
                );
            }
        } else {
            self.pending_comments.clear();
        }
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
            code_span: None,
            cst_stream: cst_events.into(),
            suppress_re: Regex::new(r"suppress: ([\w\s,]+)").unwrap(),
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
                // Pending comments refer to the line that has just ended,
                // but only if the line contains some code. If not, they keep
                // waiting for a code span.
                if let Some(code_span) = self.code_span.take() {
                    self.process_pending_comments(&code_span);
                }
            }
            Event::Token { kind: SyntaxKind::COMMENT, ref span } => {
                let comment =
                    self.cst_stream.source().get(span.range()).unwrap();
                // A comment that appears after some code in the same line
                // refers to that code, the rest must wait until the code
                // span is known.
                if let Some(code_span) = &self.code_span {
                    if let Some(hook) = &mut self.f {
                        Self::process_comment(
                            &self.suppress_re,
                            hook,
                            comment,
                            code_span,
                        );
                    }
                } else {
                    self.pending_comments.push(comment);
                }
            }
            Event::Token { ref span, .. } => {
                if let Some(code_span) = &mut self.code_span {
                    self.code_span = Some(code_span.combine(span));
                } else {
                    self.code_span = Some(span.clone())
                };
            }
            Event::Begin { kind, ref span }
                if kind == SyntaxKind::RULE_DECL
                    || kind == SyntaxKind::PATTERN_DEF =>
            {
                self.process_pending_comments(span);
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
rule test_1 { // suppress: bar
    // suppress: baz
    condition: true
}

// suppress: foo
rule test_2 { strings: /* suppress: bar */ $a = { 00 01 } condition: true }
        ",
        );

        let mut map: HashMap<&str, Vec<Span>> = HashMap::new();

        let cst =
            WarningSuppressionHook::from(parser).hook(|warning, span| {
                map.entry(warning).or_default().push(span);
            });

        let _ = cst.collect::<Vec<Event>>();

        let expected: HashMap<_, _> = vec![
            // foo is suppressed for the whole rules test_1 and test_2
            ("foo", vec![Span(18..91), Span(110..185)]),
            // bar is suppressed for "rule test_1 {" and "rule test_2 { strings: "
            ("bar", vec![Span(18..31), Span(110..132)]),
            // baz is suppressed for "condition: true"
            ("baz", vec![Span(74..89)]),
        ]
        .into_iter()
        .collect();

        assert_eq!(map, expected);
    }

    #[test]
    fn multi_warning_suppression() {
        let parser = Parser::new(
            b"
// suppress: foo, bar
rule test_1 {
    // suppress: baz, qux
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
            ("foo", vec![Span(23..84)]),
            ("bar", vec![Span(23..84)]),
            ("baz", vec![Span(67..82)]),
            ("qux", vec![Span(67..82)]),
        ]
        .into_iter()
        .collect();

        assert_eq!(map, expected);
    }

    #[test]
    fn consecutive_comments() {
        let parser = Parser::new(
            b"
// suppress: foo
//

/* suppress: bar */ /* suppress: baz */


rule test_1 {
    strings:
        // suppress: qux
        //
        $a = { 00 01 }
    condition:
        // suppress: foo
        //

        true
}
// suppress: bar
//
        ",
        );

        let mut map: HashMap<&str, Vec<Span>> = HashMap::new();

        let cst =
            WarningSuppressionHook::from(parser).hook(|warning, span| {
                map.entry(warning).or_default().push(span);
            });

        let _ = cst.collect::<Vec<Event>>();

        let expected: HashMap<_, _> = vec![
            // foo is suppressed for the whole rule test_1 and for "true"
            ("foo", vec![Span(64..216), Span(210..214)]),
            // bar and baz are suppressed for the whole rule test_1, the
            // last comment is not followed by any code.
            ("bar", vec![Span(64..216)]),
            ("baz", vec![Span(64..216)]),
            // qux is suppressed for "$a = { 00 01 }"
            ("qux", vec![Span(135..149)]),
        ]
        .into_iter()
        .collect();

        assert_eq!(map, expected);
    }
}
