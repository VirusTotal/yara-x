use std::collections::VecDeque;

use crate::cst::{Event, SyntaxKind};
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
}

impl SyntaxStream {
    /// Creates a new [`SyntaxStream`].
    pub(crate) fn new() -> Self {
        Self {
            events: VecDeque::new(),
            open_begins: VecDeque::new(),
            num_bookmarks: 0,
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
        self.events.push_back(Event::Begin(kind));
        self.open_begins.push_back(pos);
    }

    /// Pushes a [`Event::End`] at the end of the stream, closing the block
    /// that was opened by a previous call to [`SyntaxStream::begin`].
    ///
    /// # Panics
    ///
    /// * If no matching `Begin` exists for this `End`.
    pub(crate) fn end(&mut self) {
        match self.last_open_begin() {
            Some((_, kind)) => {
                self.open_begins.pop_back().unwrap();
                self.events.push_back(Event::End(kind))
            }
            None => {
                panic!("`End` without a corresponding `Begin`")
            }
        }
    }

    /// Similar to [`SyntaxStream::end`], but the kind of the closed block is
    /// changed to [`SyntaxKind::ERROR`].
    ///
    /// # Panics
    ///
    /// * If no matching `Begin` exists for this `End`.
    pub(crate) fn end_with_error(&mut self) {
        match self.last_open_begin() {
            Some((pos, _)) => {
                let node = self.events.get_mut(pos).unwrap();
                *node = Event::Begin(SyntaxKind::ERROR);
                self.events.push_back(Event::End(SyntaxKind::ERROR));
                self.open_begins.pop_back().unwrap();
            }
            None => {
                panic!("`End` without a corresponding `Begin`")
            }
        }
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
        self.events.truncate(bookmark.0)
    }

    pub(crate) fn remove_bookmark(&mut self, bookmark: Bookmark) {
        assert!(bookmark.0 <= self.events.len());
        self.num_bookmarks = self
            .num_bookmarks
            .checked_sub(1)
            .expect("dropping a bookmark twice");
    }

    pub(crate) fn last_open_begin(&self) -> Option<(usize, SyntaxKind)> {
        let pos = self.open_begins.back()?;
        let node = self.events.get(*pos)?;

        let kind = match node {
            Event::Begin(kind) => kind,
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
        s.push_token(SyntaxKind::R_BRACE, Span(0..1));
        s.push_token(SyntaxKind::L_BRACE, Span(1..2));
        s.truncate(&bookmark);
        s.push_token(SyntaxKind::R_BRACE, Span(0..1));
        s.push_token(SyntaxKind::L_BRACE, Span(1..2));
        s.truncate(&bookmark);
        s.remove_bookmark(bookmark);
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
        assert_eq!(s.pop(), Some(Event::Begin(SyntaxKind::ERROR)));
        assert_eq!(
            s.pop(),
            Some(Event::Token { kind: SyntaxKind::COLON, span: Span(0..1) })
        );
        assert_eq!(s.pop(), Some(Event::End(SyntaxKind::ERROR)));

        let mut s = SyntaxStream::new();
        s.begin(SyntaxKind::RULE_DECL);
        s.end_with_error();
        assert_eq!(s.pop(), Some(Event::Begin(SyntaxKind::ERROR)));
        assert_eq!(s.pop(), Some(Event::End(SyntaxKind::ERROR)));
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
