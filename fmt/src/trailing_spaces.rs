use std::collections::VecDeque;

use crate::tokens::categories::CONTROL;
use crate::tokens::{Token, TokenStream};

/// Pipeline that removes trailing spaces.
pub(crate) struct RemoveTrailingSpaces<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    output_buffer: VecDeque<Token<'a>>,
}

impl<'a, T> RemoveTrailingSpaces<'a, T>
where
    T: TokenStream<'a>,
{
    pub fn new(input: T) -> Self {
        Self { input, output_buffer: VecDeque::new() }
    }
}

impl<'a, T> Iterator for RemoveTrailingSpaces<'a, T>
where
    T: TokenStream<'a>,
{
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // If there's some token in the output buffer, return it.
        if let Some(next) = self.output_buffer.pop_front() {
            return Some(next);
        }

        // No tokens in the output buffer, read tokens from input.
        for next in self.input.by_ref() {
            match next {
                // Keep pushing tokens into the buffer while they are
                // whitespaces
                Token::Whitespace => {
                    self.output_buffer.push_back(next);
                }
                // If we find a newline, discard all whitespaces previously
                // buffered (control tokens are retained), put the newline
                // in the buffer, and return the first token in the buffer.
                Token::Newline => {
                    self.output_buffer.retain(|token| token.is(*CONTROL));
                    self.output_buffer.push_back(next);
                    return self.output_buffer.pop_front();
                }
                // If we find any other token, put it in the buffer. If the
                // token is a control token continue in the loop, if not,
                // return the first token in the output buffer.
                _ => {
                    if next.is(*CONTROL) {
                        self.output_buffer.push_back(next);
                    } else {
                        self.output_buffer.push_back(next);
                        return self.output_buffer.pop_front();
                    }
                }
            }
        }

        // At this point we have reached the end of the input, return the first
        // token in the output buffer, if any.
        self.output_buffer.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use crate::tokens::Token;
    use crate::trailing_spaces::RemoveTrailingSpaces;
    use pretty_assertions::assert_eq;

    #[test]
    fn test1() {
        let input = vec![Token::Whitespace, Token::Whitespace, Token::Newline];

        let output = RemoveTrailingSpaces::new(input.into_iter())
            .collect::<Vec<Token>>();

        assert_eq!(output, vec![Token::Newline,])
    }

    #[test]
    fn test2() {
        let input =
            vec![Token::Whitespace, Token::Keyword(b"foo"), Token::Newline];

        let output = RemoveTrailingSpaces::new(input.into_iter())
            .collect::<Vec<Token>>();

        assert_eq!(
            output,
            vec![Token::Whitespace, Token::Keyword(b"foo"), Token::Newline]
        )
    }
}
