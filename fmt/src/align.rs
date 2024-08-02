use std::collections::VecDeque;

use crate::tokens::Token::*;
use crate::tokens::{Token, TokenStream};

/// Makes sure that all occurrences of [`AlignmentMarker`] in a token stream
/// are replaced with zero or more whitespaces in order to force all the
/// markers within the same alignment block to be at the same column.
///
/// This is useful for converting this...
///
/// ```text
///     $short = "foo"
///     $very_long = "bar"
///     $even_longer = "baz"
///  ```
///
///  into this...
///  
/// ```text
///     $short       = "foo"
///     $very_long   = "bar"
///     $even_longer = "baz"
/// ```
///
/// This is done by inserting an [`AlignmentMarker`] in front of every equal
/// sign token in a rule declaration, and enclosing all the declarations in
/// a block using the [`AlignmentBlockBegin`] and [`AlignmentBlockEnd`] tokens
/// for indicating the block's start and ending point. Once this is done, the
/// resulting token stream is passed to [`Aligner`].
///
/// Notice that [`Aligner`] requires that the input stream already contains  
/// at least one newline token after each pattern declaration.
///
pub(crate) struct Align<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    output_buffer: VecDeque<Token<'a>>,
}

impl<'a, T> Align<'a, T>
where
    T: TokenStream<'a>,
{
    pub fn new(input: T) -> Self {
        Self { input, output_buffer: VecDeque::new() }
    }
}

impl<'a, T> Iterator for Align<'a, T>
where
    T: TokenStream<'a>,
{
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // If there's some token in the output buffer, return it.
        if let Some(next) = self.output_buffer.pop_front() {
            return Some(next);
        }
        // No tokens in the output buffer, take a token from input.
        let next = self.input.next()?;

        // If next token indicates the start of an alignment block, process
        // the block, if not, return the token.
        if matches!(next, AlignmentBlockBegin) {
            let mut column = 0;
            let mut marker_columns = Vec::new();
            let mut block_tokens = VecDeque::new();

            for token in self.input.by_ref() {
                match token {
                    AlignmentBlockBegin => {
                        unreachable!("nested alignment blocks are not allowed")
                    }
                    AlignmentBlockEnd => {
                        break;
                    }
                    AlignmentMarker => {
                        // When some alignment marker appears inside the block
                        // store its column number.
                        marker_columns.push(column);
                        block_tokens.push_back(token);
                    }
                    Newline => {
                        // When a new line character is found, the
                        // column number is reset to zero.
                        column = 0;
                        block_tokens.push_back(token);
                    }
                    _ => {
                        // With every other token the column number is
                        // incremented by the token's length.
                        column += token.as_bytes().len();
                        block_tokens.push_back(token);
                    }
                }
            }

            let max_column = marker_columns.iter().max().cloned().unwrap_or(0);
            let mut marker_index = 0;
            // All tokens in the block are now in block_tokens. They
            // are transferred to output_buffer while replacing
            // alignment markers with a variable length of spaces.
            for token in block_tokens {
                if token == AlignmentMarker {
                    for _ in 0..max_column - marker_columns[marker_index] {
                        self.output_buffer.push_back(Whitespace);
                    }
                    marker_index += 1;
                } else {
                    self.output_buffer.push_back(token);
                }
            }

            self.output_buffer.pop_front()
        } else {
            Some(next)
        }
    }
}
