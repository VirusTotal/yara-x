use crate::{Token, TokenStream};
use std::collections::VecDeque;

/// Pipeline that insert spaces for indenting code.
///
/// This pipeline expects a token stream that contains indentation tokens
/// (i.e: [`Token::Indentation`]) for increasing/decreasing the indentation
/// level. These tokens are removed from the output, and the appropriate
/// number of spaces is inserted after each newline for indenting the code
/// to its corresponding level.

pub(crate) struct AddIndentationSpaces<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    indent_level: i16,
    num_spaces: u8,
    output_buffer: VecDeque<Token<'a>>,
}

impl<'a, T> AddIndentationSpaces<'a, T>
where
    T: TokenStream<'a>,
{
    pub fn new(input: T, num_spaces: u8) -> Self {
        Self {
            input,
            num_spaces,
            indent_level: 0,
            output_buffer: VecDeque::new(),
        }
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
                // Indentation tokens alter the current indentation level. The
                // value for `delta` can be positive and negative.
                Token::Indentation(delta) => {
                    self.indent_level += delta;
                }
                // After each newline insert the appropriate number of spaces
                // for indenting the line to the current level.
                Token::Newline => {
                    self.output_buffer.push_back(Token::Newline);
                    for _ in 0..self.indent_level {
                        if self.num_spaces == 0 {
                            self.output_buffer.push_back(Token::Tab);
                        } else {
                            for _ in 0..self.num_spaces {
                                self.output_buffer
                                    .push_back(Token::Whitespace);
                            }
                        }
                    }
                    return self.output_buffer.pop_front();
                }
                // Any other token goes directly to the output.
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
