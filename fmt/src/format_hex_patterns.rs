use std::collections::VecDeque;
use yara_x_parser::cst::SyntaxKind;

use crate::tokens::{Token, TokenStream};

/// Pipeline that formats hex patterns.
pub(crate) struct FormatHexPatterns<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    output_buffer: VecDeque<Token<'a>>,
    buffering: bool,
    in_hex_pattern: bool,
    multi_line: bool,
}

impl<'a, T> FormatHexPatterns<'a, T>
where
    T: TokenStream<'a>,
{
    pub fn new(input: T) -> Self {
        Self {
            input,
            output_buffer: VecDeque::new(),
            buffering: false,
            in_hex_pattern: false,
            multi_line: false,
        }
    }
}

impl<'a, T> Iterator for FormatHexPatterns<'a, T>
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
                Token::Begin(SyntaxKind::HEX_PATTERN) => {
                    self.in_hex_pattern = true;
                    self.multi_line = false;
                    self.buffering = false;
                    self.output_buffer.push_back(next);
                    return self.output_buffer.pop_front();
                }
                Token::End(SyntaxKind::HEX_PATTERN) => {
                    self.in_hex_pattern = false;
                    self.output_buffer.push_back(next);
                    return self.output_buffer.pop_front();
                }
                // When the opening brace (`{`) is found, start buffering the
                // next tokens until finding a newline.
                Token::Punctuation(b"{") if self.in_hex_pattern => {
                    self.buffering = true;
                    self.output_buffer.push_back(next);
                    return self.output_buffer.pop_front();
                }
                // When the closing brace (`}`) is found, insert a newline in
                // front of it if the pattern is multiline and the newline
                // doesn't exist already.
                Token::Punctuation(b"}") if self.in_hex_pattern => {
                    match self.output_buffer.back() {
                        Some(Token::Newline) | None => {
                            self.output_buffer.push_back(next);
                        }
                        _ => {
                            if self.multi_line {
                                self.output_buffer.push_back(Token::Newline);
                            }
                            self.output_buffer.push_back(next);
                        }
                    }
                    return self.output_buffer.pop_front();
                }
                // When a newline is found inside the hex pattern, insert
                // a newline after the opening brace if it didn't exist.
                Token::Newline if self.in_hex_pattern => {
                    self.output_buffer.push_back(next);
                    // If this is the first line (multi_line is still false),
                    // insert of a newline at the front of the output buffer
                    // if not already there. This inserts a newline after the
                    // opening { for multi-line patterns.
                    if !self.multi_line
                        && !matches!(
                            self.output_buffer.front(),
                            Some(Token::Newline)
                        )
                    {
                        self.output_buffer.push_front(Token::Newline)
                    }

                    self.multi_line = true;
                    return self.output_buffer.pop_front();
                }
                _ => {
                    self.output_buffer.push_back(next);
                    if !self.buffering {
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
