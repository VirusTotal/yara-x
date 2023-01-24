use crate::{Token, TokenStream};
use std::collections::VecDeque;

/// Pipeline that insert spaces for indenting code.
pub(crate) struct AddIndentationSpaces<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    indent_level: i16,
    output_buffer: VecDeque<Token<'a>>,
}

impl<'a, T> AddIndentationSpaces<'a, T>
where
    T: TokenStream<'a>,
{
    pub fn new(input: T) -> Self {
        Self { input, indent_level: 0, output_buffer: VecDeque::new() }
    }
}

impl<'a, T> Iterator for AddIndentationSpaces<'a, T>
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
        for token in self.input.by_ref() {
            match token {
                Token::Indentation(increase) => {
                    self.indent_level += increase;
                }
                Token::Newline => {
                    self.output_buffer.push_back(Token::Newline);
                    for _ in 0..self.indent_level {
                        // Indent with two spaces per level
                        self.output_buffer.push_back(Token::Whitespace);
                        self.output_buffer.push_back(Token::Whitespace);
                    }
                    return self.output_buffer.pop_front();
                }
                _ => {
                    self.output_buffer.push_back(token);
                    return self.output_buffer.pop_front();
                }
            }
        }

        // At this point we have reached the end of the input, return the first
        // token in the output buffer, if any.
        self.output_buffer.pop_front()
    }
}
