use itertools::Itertools;
use std::collections::VecDeque;

use crate::tokenizer::{Token, Tokenizer};

/// `TokenStream` extends [`Tokenizer`] by adding infinite lookahead and backtracking.
///
/// Unlike [`Tokenizer`], which only provides a simple API that returns tokens in a
/// sequential way, `TokenStream` allows:
///
/// - Peeking at upcoming tokens without consuming them.
/// - Rewinding to previously consumed tokens.
///
/// These features are essential for PEG parsers. `TokenStream` wraps a [`Tokenizer`]
/// and enhances it with:
///
/// - [`TokenStream::next_token`]: Advances to the next token, similar to [`Tokenizer::next_token`].
/// - [`TokenStream::peek_token`]: Peeks at  upcoming tokens without advancing.
/// - [`TokenStream::bookmark`]: Creates a bookmark in the stream.
/// - [`TokenStream::restore_bookmark`]: Restores the stream to a bookmarked position.
///
pub struct TokenStream<'src> {
    /// The tokenizer from where the tokens are retrieved.
    tokenizer: Tokenizer<'src>,
    /// Temporary token storage. Tokens are obtained from the tokenizer and
    /// pushed into this deque for later consumption.
    tokens: VecDeque<Token>,
    /// Existing bookmarks. Each bookmark is the absolute index of the token
    /// being bookmarked. This is kept sorted in ascending order, the leftmost
    /// bookmark is always at the front of the deque.
    bookmarks: VecDeque<usize>,
    /// Absolute index of the current token. Tokens are indexed as 0, 1, 2,
    /// etc. With absolute, we mean that the position is not an index in the
    /// `tokens` deque, but the position of the token in the overall stream
    /// of tokens.
    current_token: usize,
    /// Number of tokens that have been purged (i.e: removed from the left of
    /// `tokens`). The `tokens` deque is purged frequently, in order to remove
    /// tokens that won't be returned again.
    purged_tokens: usize,
}

impl<'src> TokenStream<'src> {
    /// Creates a new `TokenStream` that uses `tokenizer` as its source of
    /// tokens.
    pub fn new(tokenizer: Tokenizer<'src>) -> Self {
        Self {
            tokenizer,
            tokens: VecDeque::new(),
            bookmarks: VecDeque::new(),
            current_token: 0,
            purged_tokens: 0,
        }
    }

    /// Returns the source associated to this token stream.
    #[inline]
    pub fn source(&self) -> &'src [u8] {
        self.tokenizer.source()
    }

    /// Returns the index of the current token.
    ///
    /// Tokens in the stream have an associated zero-based index. The first
    /// token is 0, the second is 1, etc. This function returns the index
    /// of the current token.
    pub fn current_token_index(&self) -> usize {
        self.current_token
    }

    /// Returns the current token and advance to the next one.
    ///
    /// Returns `None` if the end of the stream has been reached.
    pub fn next_token(&mut self) -> Option<Token> {
        self.fetch_tokens(self.current_token);
        let token = self.tokens.get(self.rel_pos(self.current_token)).cloned();
        if token.is_some() {
            self.bump();
        }
        token
    }

    /// Returns the N-th token after the current one, without advancing the
    /// stream position.
    ///
    /// Returns `None` when peeking a token past the end of the stream.
    pub fn peek_token(&mut self, n: usize) -> Option<&Token> {
        self.fetch_tokens(self.current_token + n);
        let token = self.tokens.get(self.rel_pos(self.current_token + n));
        token
    }

    /// Returns true if the stream has more tokens to return.
    #[inline]
    pub fn has_more(&mut self) -> bool {
        self.peek_token(0).is_some()
    }

    /// Returns a bookmark for the current stream position.
    ///
    /// By passing the bookmark to [`TokenStream::restore_bookmark`] you can go back
    /// to a previous stream position.
    pub fn bookmark(&mut self) -> Bookmark {
        match self.bookmarks.back() {
            // No bookmarks yet, simply insert at the end.
            None => {
                self.bookmarks.push_back(self.current_token);
            }
            // There are bookmarks, but the rightmost one is lower than the
            // current offset, inserting at the end keeps the order.
            Some(rightmost) if *rightmost <= self.current_token => {
                self.bookmarks.push_back(self.current_token)
            }
            // There are bookmarks, but they need to be sorted after insertion.
            Some(_) => {
                self.bookmarks.push_back(self.current_token);
                self.bookmarks.make_contiguous().sort();
            }
        }
        Bookmark(self.current_token)
    }

    /// Restores the stream to a position previously bookmarked with
    /// [`TokenStream::bookmark`].
    #[inline]
    pub fn restore_bookmark(&mut self, bookmark: &Bookmark) {
        self.current_token = bookmark.0;
    }

    /// Drops a bookmark.
    ///
    /// By dropping a bookmark you tell the stream that you don't intend to go
    /// back to the bookmarked position again, therefore is safe for the stream
    /// to purge past tokens that are not reachable anymore because there are
    /// no bookmarks pointing to them.
    ///
    /// # Panics
    ///
    /// If the bookmark doesn't exist or was previously removed.
    pub fn remove_bookmark(&mut self, bookmark: Bookmark) {
        match self.bookmarks.iter().find_position(|b| **b == bookmark.0) {
            Some((pos, _)) => {
                self.bookmarks.remove(pos);
            }
            None => {
                panic!("trying to remove a non-existing bookmark");
            }
        }
    }

    /// Switches to hex pattern operation mode.
    ///
    /// See: [`Tokenizer::enter_hex_pattern_mode`].
    #[inline]
    pub fn enter_hex_pattern_mode(&mut self) {
        self.tokenizer.enter_hex_pattern_mode()
    }

    /// Switches to hex jump operation mode.
    ///
    /// See: [`Tokenizer::enter_hex_jump_mode`].
    #[inline]
    pub fn enter_hex_jump_mode(&mut self) {
        self.tokenizer.enter_hex_jump_mode()
    }
}

impl<'src> TokenStream<'src> {
    /// Fetch tokens from the underlying tokenizer until reaching the given
    /// absolute position.
    fn fetch_tokens(&mut self, abs_pos: usize) {
        while self.rel_pos(abs_pos) >= self.tokens.len() {
            match self.tokenizer.next_token() {
                Some(token) => self.tokens.push_back(token),
                None => break,
            }
        }
    }

    /// Advances the stream position by one.
    #[inline]
    fn bump(&mut self) {
        self.current_token += 1;
        self.purge();
    }

    /// Remove all tokens that were already returned and won't be necessary
    /// anymore.
    ///
    /// The tokens that can be removed are all those that are at the left of
    /// the leftmost bookmark, if a bookmark exist, or at the left of the
    /// current token.
    fn purge(&mut self) {
        let n = if let Some(leftmost_bookmark) = self.bookmarks.front() {
            // Ensure that the token referenced by the left-most bookmark has
            // not being purged yet.
            assert!(*leftmost_bookmark >= self.purged_tokens);
            // Purge all tokens at the left of the left-most bookmark.
            self.rel_pos(*leftmost_bookmark)
        } else {
            // Purge all tokens at the left of the current token.
            self.rel_pos(self.current_token)
        };

        for _ in 0..n {
            self.tokens.pop_front();
        }

        self.purged_tokens += n;
    }

    /// Converts an absolute position to a relative one.
    fn rel_pos(&self, abs_pos: usize) -> usize {
        abs_pos - self.purged_tokens
    }
}

pub struct Bookmark(usize);

#[cfg(test)]
mod test {
    use crate::parser::token_stream::TokenStream;
    use crate::tokenizer::{Token, Tokenizer};
    use crate::Span;

    #[test]
    fn next() {
        let mut t = TokenStream::new(Tokenizer::new(b"uno dos tres"));

        assert_eq!(t.current_token, 0);
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(0..3))));
        assert_eq!(t.current_token, 1);
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.current_token, 2);
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));
        assert_eq!(t.current_token, 3);
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(7..8))));
        assert_eq!(t.current_token, 4);
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(8..12))));
        assert_eq!(t.current_token, 5);
        assert_eq!(t.next_token(), None);
        assert_eq!(t.current_token, 5);
        assert_eq!(t.next_token(), None);
        assert_eq!(t.current_token, 5);
    }

    #[test]
    fn peek_and_bump() {
        let mut t = TokenStream::new(Tokenizer::new(b"uno dos tres"));

        assert_eq!(t.peek_token(0), Some(&Token::IDENT(Span(0..3))));
        assert_eq!(t.peek_token(1), Some(&Token::WHITESPACE(Span(3..4))));

        t.bump();
        assert_eq!(t.peek_token(0), Some(&Token::WHITESPACE(Span(3..4))));
        t.bump();
        assert_eq!(t.peek_token(0), Some(&Token::IDENT(Span(4..7))));
        t.bump();
        assert_eq!(t.peek_token(0), Some(&Token::WHITESPACE(Span(7..8))));
        t.bump();
        assert_eq!(t.peek_token(0), Some(&Token::IDENT(Span(8..12))));
        t.bump();
        assert_eq!(t.peek_token(0), None);
        t.bump();
        assert_eq!(t.peek_token(0), None);
    }

    #[test]
    fn bookmarks_1() {
        let mut t = TokenStream::new(Tokenizer::new(b"uno dos tres"));

        let b = t.bookmark();

        assert_eq!(t.next_token(), Some(Token::IDENT(Span(0..3))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(7..8))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(8..12))));
        assert_eq!(t.next_token(), None);

        t.restore_bookmark(&b);

        assert_eq!(t.next_token(), Some(Token::IDENT(Span(0..3))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(7..8))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(8..12))));
        assert_eq!(t.next_token(), None);

        t.restore_bookmark(&b);
        t.remove_bookmark(b);

        assert_eq!(t.next_token(), Some(Token::IDENT(Span(0..3))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(7..8))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(8..12))));
        assert_eq!(t.next_token(), None);
    }

    #[test]
    fn bookmarks_2() {
        let mut t = TokenStream::new(Tokenizer::new(b"uno dos tres"));

        assert_eq!(t.next_token(), Some(Token::IDENT(Span(0..3))));

        let b1 = t.bookmark();

        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));

        t.restore_bookmark(&b1);

        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));

        let b2 = t.bookmark();

        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(7..8))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(8..12))));

        t.restore_bookmark(&b2);
        t.remove_bookmark(b2);

        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(7..8))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(8..12))));
        assert_eq!(t.next_token(), None);

        t.restore_bookmark(&b1);

        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));
        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(7..8))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(8..12))));
        assert_eq!(t.next_token(), None);
    }

    #[test]
    fn bookmarks_3() {
        let mut t = TokenStream::new(Tokenizer::new(b"uno dos tres"));

        assert_eq!(t.next_token(), Some(Token::IDENT(Span(0..3))));

        let b1 = t.bookmark();
        let b2 = t.bookmark();
        let b3 = t.bookmark();

        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));

        t.remove_bookmark(b3);
        t.restore_bookmark(&b2);

        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));

        t.remove_bookmark(b2);
        t.restore_bookmark(&b1);

        assert_eq!(t.next_token(), Some(Token::WHITESPACE(Span(3..4))));
        assert_eq!(t.next_token(), Some(Token::IDENT(Span(4..7))));

        t.remove_bookmark(b1);
    }
}
