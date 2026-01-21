use std::collections::VecDeque;
use std::iter::Peekable;

use crate::cst::{Event, SyntaxKind};

/// An iterator that merges consecutive `ERROR` events from a stream of
/// [`Event`]s.
///
/// This iterator wraps another [`Event`] iterator and processes its output.
/// The main goal is to identify sequences of adjacent `ERROR` events and
/// merge them into a single, larger `ERROR` event.
///
/// For example, if the underlying iterator produces the events:
///
/// ```text
///  Event::Begin { kind: ERROR, .. }
///  .. sequence of tokens 1
///  Event::End { kind: ERROR, .. }
///  Event::Begin { kind: ERROR, .. }
///  .. sequence of tokens 2
///  Event::End { kind: ERROR, .. }
/// ```
///
/// The output from the `ErrorMerge` iterator will be:
///
/// ```text
///  Event::Begin { kind: ERROR, .. }
///  .. sequence of tokens 1
///  .. sequence of tokens 2
///  Event::End { kind: ERROR, .. }
/// ```
///
/// This useful to improve the output of `SyntaxStream`, which can contain
/// consecutive `ERROR` nodes.
pub struct ErrorMerger<I>
where
    I: Iterator<Item = Event>,
{
    inner: Peekable<I>,
    /// Contains the indexes within output_buffer occupied by Event::Begin
    /// for which we don't have the Event::End yet.
    open_begins: Vec<usize>,
    output_buffer: VecDeque<Event>,
}

impl<I> ErrorMerger<I>
where
    I: Iterator<Item = Event>,
{
    /// Creates a new [`ErrorMerger`] that wraps the given iterator.
    pub fn new(inner: I) -> Self {
        Self {
            inner: inner.peekable(),
            open_begins: Vec::new(),
            output_buffer: VecDeque::new(),
        }
    }
}

impl<I> Iterator for ErrorMerger<I>
where
    I: Iterator<Item = Event>,
{
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(event) = self.output_buffer.pop_front() {
            return Some(event);
        }

        while let Some(event) = self.inner.next() {
            match event {
                // Found the start of an ERROR, push it into `output_buffer`
                // and save its index in `open_begins` until we find the
                // matching Event::End.
                event @ Event::Begin { kind: SyntaxKind::ERROR, .. } => {
                    self.open_begins.push(self.output_buffer.len());
                    self.output_buffer.push_back(event);
                }
                // Found an Event::End indicating the end of an error.
                Event::End { kind: SyntaxKind::ERROR, .. } => {
                    match self.inner.peek() {
                        // The next event is the start of another error. The
                        // next error will be merged with the current one.
                        Some(Event::Begin {
                            kind: SyntaxKind::ERROR,
                            span: next_error_span,
                        }) => {
                            // The span of the `Event::Begin` that corresponds
                            // to the current error is updated so that it covers
                            // the span of the both the current and the next
                            // error.
                            let begin_idx = self.open_begins.last().unwrap();
                            match &mut self.output_buffer[*begin_idx] {
                                Event::Begin {
                                    kind: SyntaxKind::ERROR,
                                    span,
                                } => {
                                    *span = span.combine(next_error_span);
                                }
                                _ => unreachable!(),
                            }
                            // Drop the `Event::Begin` indicating the start of
                            // the next error. The `Event::End` indicating the
                            // end of the previous one is also dropped, which
                            // means that both errors are now merged.
                            self.inner.next();
                        }
                        // The next event is not the start of an error. Proceed to
                        // put the `Event::End` for the current error into the
                        // output buffer.
                        _ => {
                            let begin_idx = self.open_begins.pop().unwrap();
                            let span = match &self.output_buffer[begin_idx] {
                                Event::Begin {
                                    kind: SyntaxKind::ERROR,
                                    span,
                                } => span.clone(),
                                _ => unreachable!(),
                            };
                            self.output_buffer.push_back(Event::End {
                                kind: SyntaxKind::ERROR,
                                span,
                            });
                        }
                    }
                }
                event => {
                    self.output_buffer.push_back(event);
                    if self.open_begins.is_empty() {
                        break;
                    }
                }
            }
        }

        assert!(self.open_begins.is_empty());
        self.output_buffer.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use crate::cst::error_merger::ErrorMerger;
    use crate::cst::Event;
    use crate::cst::SyntaxKind;
    use crate::Span;

    #[test]
    fn error_merger() {
        let events = vec![
            Event::Begin { kind: SyntaxKind::ERROR, span: Span(0..20) },
            Event::Token { kind: SyntaxKind::WHITESPACE, span: Span(0..10) },
            Event::Begin { kind: SyntaxKind::ERROR, span: Span(10..20) },
            Event::Token { kind: SyntaxKind::WHITESPACE, span: Span(10..20) },
            Event::End { kind: SyntaxKind::ERROR, span: Span(10..20) },
            Event::End { kind: SyntaxKind::ERROR, span: Span(0..20) },
            Event::Begin { kind: SyntaxKind::ERROR, span: Span(20..30) },
            Event::Token { kind: SyntaxKind::WHITESPACE, span: Span(20..30) },
            Event::End { kind: SyntaxKind::ERROR, span: Span(20..30) },
            Event::Begin { kind: SyntaxKind::ERROR, span: Span(30..40) },
            Event::Token { kind: SyntaxKind::WHITESPACE, span: Span(30..40) },
            Event::End { kind: SyntaxKind::ERROR, span: Span(30..40) },
        ];

        let mut stream = ErrorMerger::new(events.into_iter());

        assert_eq!(
            stream.next(),
            Some(Event::Begin { kind: SyntaxKind::ERROR, span: Span(0..40) })
        );

        assert_eq!(
            stream.next(),
            Some(Event::Token {
                kind: SyntaxKind::WHITESPACE,
                span: Span(0..10)
            })
        );

        assert_eq!(
            stream.next(),
            Some(Event::Begin { kind: SyntaxKind::ERROR, span: Span(10..20) })
        );

        assert_eq!(
            stream.next(),
            Some(Event::Token {
                kind: SyntaxKind::WHITESPACE,
                span: Span(10..20)
            })
        );

        assert_eq!(
            stream.next(),
            Some(Event::End { kind: SyntaxKind::ERROR, span: Span(10..20) })
        );

        assert_eq!(
            stream.next(),
            Some(Event::Token {
                kind: SyntaxKind::WHITESPACE,
                span: Span(20..30)
            })
        );

        assert_eq!(
            stream.next(),
            Some(Event::Token {
                kind: SyntaxKind::WHITESPACE,
                span: Span(30..40)
            })
        );

        assert_eq!(
            stream.next(),
            Some(Event::End { kind: SyntaxKind::ERROR, span: Span(0..40) })
        );
    }
}
