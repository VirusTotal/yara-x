use std::collections::VecDeque;

use crate::cst::Event;
use crate::cst::SyntaxKind;
use crate::Span;

/// A Concrete Syntax Tree (CST) represented as a stream of events.
///
/// See the documentation for [`crate::cst::CSTStream`], which is the public
/// facing API that exposes the concept to the public.
pub struct SyntaxStream {
    events: VecDeque<Event>,
    /// Positions within `events` where `Begin` events are located. This allows
    /// locating the last `Begin` event without having to traverse `events`
    /// right-to-left.
    open_begins: VecDeque<usize>,
    /// Number of currently active bookmarks.
    num_bookmarks: usize,
    /// The span of the last token in the stream.
    last_token_span: Span,
}

impl SyntaxStream {
    /// Creates a new [`SyntaxStream`].
    pub(crate) fn new() -> Self {
        Self {
            events: VecDeque::new(),
            open_begins: VecDeque::new(),
            num_bookmarks: 0,
            last_token_span: Span::default(),
        }
    }

    /// Removes an event from the beginning of the stream and returns it.
    ///
    /// There are some restrictions for this operation:
    ///
    /// * The stream can't have any active bookmarks.
    /// * Every `Begin` must already have a matching `End`.
    ///
    /// # Panics
    ///
    /// If any of the conditions mentioned above is not met.
    #[inline]
    pub(crate) fn pop(&mut self) -> Option<Event> {
        // A bookmark is a position in `events`, therefore calling this
        // function invalidates any existing bookmark. Make sure that
        // there's no existing bookmarks.
        assert_eq!(self.num_bookmarks, 0);

        // Ensure that all `Begin` events have its corresponding `End`.
        assert!(self.open_begins.is_empty());

        let event = self.events.pop_front();
        if event.is_some() {
            for b in self.open_begins.iter_mut() {
                *b -= 1;
            }
        }
        event
    }

    /// Pushes a [`Event::Token`] at the end of the stream.
    #[inline]
    pub(crate) fn push_token(&mut self, kind: SyntaxKind, span: Span) {
        self.last_token_span = span.clone();
        self.events.push_back(Event::Token { kind, span })
    }

    /// Pushes a [`Event::Error`] at the end of the stream.
    #[inline]
    pub(crate) fn push_error<M: Into<String>>(
        &mut self,
        message: M,
        span: Span,
    ) {
        self.events.push_back(Event::Error { message: message.into(), span })
    }

    /// Pushes a [`Event::Begin`] at the end of the stream, opening a block
    /// that must be closed by a corresponding call to [`SyntaxStream::end`].
    pub(crate) fn begin(&mut self, kind: SyntaxKind) {
        let pos = self.events.len();
        let last_token_end = self.last_token_span.end();
        self.events.push_back(Event::Begin {
            kind,
            // The non-terminal represented by this Event::Begin starts where
            // the last token ends. The end is initially set to `last_token_end`
            // too, but it will be updated when Event::End is inserted in the
            // stream.
            span: Span::from(last_token_end..last_token_end),
        });
        self.open_begins.push_back(pos);
    }

    /// Pushes a [`Event::End`] at the end of the stream, closing the block
    /// that was opened by a previous call to [`SyntaxStream::begin`].
    ///
    /// # Panics
    ///
    /// * If no matching `Begin` exists for this `End`.
    pub(crate) fn end(&mut self) {
        // Get the index in the `events` vector where the `Event::Begin`
        // that corresponds to this `Event::End` resides.
        let begin_idx = self
            .open_begins
            .pop_back()
            .expect("`End` without a corresponding `Begin`");

        match &mut self.events[begin_idx] {
            Event::Begin { kind, span } => {
                // Now that we know where it ends, the span associated to
                // Event::Begin is updated.
                *span = Span::from(span.start()..self.last_token_span.end());
                // Push the Event::End that closes the Event::Begin. Both
                // have the same kind and span.
                let kind = *kind;
                let span = span.clone();
                self.events.push_back(Event::End { kind, span });
            }
            _ => unreachable!(),
        };
    }

    /// Similar to [`SyntaxStream::end`], but the kind of the closed block is
    /// changed to [`SyntaxKind::ERROR`].
    ///
    /// Notice that if the block being closed is empty, it will be removed
    /// altogether.
    ///
    /// # Panics
    ///
    /// * If no matching `Begin` exists for this `End`.
    pub(crate) fn end_with_error(&mut self) {
        // Get the index in the `events` vector where the `Event::Begin`
        // that corresponds to this `Event::End` resides.
        let begin_idx = self
            .open_begins
            .pop_back()
            .expect("`End` without a corresponding `Begin`");

        // If `Event::Begin` is the last element in `events`, there's no other
        // event in between `Event::Begin` and the current `Event::End`. In
        // such cases, the `Event::Begin` is removed and the `Event::End` not
        // inserted, we don't want empty nodes in the CST.
        if begin_idx == self.events.len() - 1 {
            self.events.pop_back();
            return;
        }

        match &mut self.events[begin_idx] {
            Event::Begin { kind, span } => {
                // Change the kind for Event::Begin to SyntaxKind::ERROR.
                *kind = SyntaxKind::ERROR;
                // Update the span's ending offset for Event::Begin.
                *span = Span::from(span.start()..self.last_token_span.end());
                let kind = *kind;
                let span = span.clone();
                self.events.push_back(Event::End { kind, span });
            }
            _ => unreachable!(),
        };
    }

    /// Returns a bookmark for the current ending position of the stream.
    pub(crate) fn bookmark(&mut self) -> Bookmark {
        self.num_bookmarks += 1;
        Bookmark(self.events.len())
    }

    /// Truncates the stream at the position indicated by the bookmark,
    /// removing any event added after the bookmark was created.
    ///
    /// # Panics
    ///
    /// If the bookmark points to a position that doesn't exist.
    pub(crate) fn truncate(&mut self, bookmark: &Bookmark) {
        assert!(bookmark.0 <= self.events.len());
        self.events.truncate(bookmark.0);

        self.last_token_span = self
            .events
            .iter()
            .rev()
            .find_map(|event| {
                if let Event::Token { span, .. } = event {
                    Some(span.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();
    }

    pub(crate) fn remove_bookmark(&mut self, bookmark: Bookmark) {
        assert!(bookmark.0 <= self.events.len());
        self.num_bookmarks = self
            .num_bookmarks
            .checked_sub(1)
            .expect("dropping a bookmark twice");
    }

    #[cfg(test)]
    pub(crate) fn last_open_begin(&self) -> Option<(usize, SyntaxKind)> {
        let pos = self.open_begins.back()?;
        let node = self.events.get(*pos)?;

        let kind = match node {
            Event::Begin { kind, .. } => kind,
            _ => panic!(),
        };

        Some((*pos, *kind))
    }
}

pub(crate) struct Bookmark(usize);

#[cfg(test)]
mod tests {
    use super::SyntaxKind;
    use super::SyntaxStream;
    use crate::cst::Event;
    use crate::Span;

    #[test]
    fn begin_and_end() {
        let mut s = SyntaxStream::new();
        s.begin(SyntaxKind::RULE_DECL);
        assert_eq!(s.last_open_begin(), Some((0, SyntaxKind::RULE_DECL)));
        s.begin(SyntaxKind::META_DEF);
        assert_eq!(s.last_open_begin(), Some((1, SyntaxKind::META_DEF)));
        s.end();
        assert_eq!(s.last_open_begin(), Some((0, SyntaxKind::RULE_DECL)));
        s.end();
        assert_eq!(s.last_open_begin(), None);
    }

    #[test]
    fn bookmarks() {
        let mut s = SyntaxStream::new();
        let bookmark = s.bookmark();
        s.push_token(SyntaxKind::L_BRACE, Span(0..1));
        s.push_token(SyntaxKind::R_BRACE, Span(1..2));
        s.truncate(&bookmark);
        s.push_token(SyntaxKind::L_BRACE, Span(0..1));
        s.push_token(SyntaxKind::R_BRACE, Span(1..2));
        s.truncate(&bookmark);
        s.remove_bookmark(bookmark);
        s.begin(SyntaxKind::EXPR);
        s.push_token(SyntaxKind::L_PAREN, Span(0..1));
        s.push_token(SyntaxKind::R_PAREN, Span(1..2));
        s.end();

        assert_eq!(
            s.pop(),
            Some(Event::Begin { kind: SyntaxKind::EXPR, span: Span(0..2) })
        );

        assert_eq!(
            s.pop(),
            Some(Event::Token { kind: SyntaxKind::L_PAREN, span: Span(0..1) })
        );

        assert_eq!(
            s.pop(),
            Some(Event::Token { kind: SyntaxKind::R_PAREN, span: Span(1..2) })
        );

        assert_eq!(
            s.pop(),
            Some(Event::End { kind: SyntaxKind::EXPR, span: Span(0..2) })
        );

        assert_eq!(s.pop(), None);
    }

    #[test]
    fn end_with_error() {
        let mut s = SyntaxStream::new();
        s.begin(SyntaxKind::RULE_DECL);
        s.begin(SyntaxKind::META_DEF);
        s.push_token(SyntaxKind::COLON, Span(0..1));
        s.end_with_error();
        assert_eq!(s.last_open_begin(), Some((0, SyntaxKind::RULE_DECL)));

        let mut s = SyntaxStream::new();
        s.begin(SyntaxKind::ERROR);
        s.push_token(SyntaxKind::COLON, Span(0..1));
        s.end_with_error();
        assert_eq!(
            s.pop(),
            Some(Event::Begin { kind: SyntaxKind::ERROR, span: Span(0..1) })
        );
        assert_eq!(
            s.pop(),
            Some(Event::Token { kind: SyntaxKind::COLON, span: Span(0..1) })
        );
        assert_eq!(
            s.pop(),
            Some(Event::End { kind: SyntaxKind::ERROR, span: Span(0..1) })
        );
    }

    #[test]
    #[should_panic]
    fn unmatched_begin_and_end() {
        let mut s = SyntaxStream::new();
        s.begin(SyntaxKind::META_DEF);
        s.begin(SyntaxKind::RULE_DECL);
        s.end();
        s.end();
        s.end();
    }

    #[test]
    #[should_panic]
    fn end_without_begin() {
        let mut s = SyntaxStream::new();
        s.end();
    }
}
