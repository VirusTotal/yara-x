use crate::{COMMENT, CONTROL, NEWLINE, WHITESPACE};
use bstr::{BStr, ByteSlice};
use std::collections::vec_deque::VecDeque;

use crate::tokens::{Token, TokenStream};

/// Converts all instances of [`Token::Comment`] into one of:
///
///  [`Token::BlockComment`],
///  [`Token::TailComment`],
///  [`Token::HeadComment`],
///  [`Token::InlineComments`]
///
/// ... depending on the token's position within the line.
///
/// For example,
///
/// ```text
/// rule test {
///   // This is a block comment
///   /* This is a head comment */ condition:
///      true // This is a tail comment
/// }
/// ```
///
/// This processor must be used with a token stream that still retains the
/// original spacing of the source code (but with tabs replaced by spaces),
/// because it needs the spacing for determining the original indentation
/// of the comment. For example:
///
/// ```text
/// rule test {
///          /*
///           *  This comment is indented
///           */
///     condition: true
/// }
/// ```
///
/// While adjusting the indentation of the code above we want the comment to
/// look like this:
///
/// ```text
/// rule test {
///     /*
///      * This comment is indented
///      */
///     condition: true
/// }
/// ```
///
/// Not like this:
///
/// ```text
/// rule test {
///     /*
///           *  This comment is indented
///           */
///     condition: true
/// }
/// ```
///
/// For achieving this we can't simply copy everything contained between
/// /* and */ verbatim, we must be able to recognize the original comment's
/// indentation and remove the extra spaces accordingly.
///
pub(crate) struct CommentProcessor<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    input_buffer: VecDeque<Token<'a>>,
    output_buffer: VecDeque<Token<'a>>,
    start_of_input: bool,
    end_of_input: bool,
    indentation: usize,
    tab_size: usize,
}

/// States used in [`CommentProcessor::process_input_buffer`]
enum State {
    /// This state indicates that a comment token has not been found yet.
    /// When a newline character is found before finding a comment,
    /// `leading_newline` is set to `true`.
    PreComment { leading_newline: bool },
    /// Once a comment token is found, it goes to this state which contains
    /// information about the comment being created.
    Comment {
        indentation: usize,
        leading_newline: bool,
        trailing_newline: bool,
        lines: Vec<Vec<u8>>,
    },
}

impl<'a, T> CommentProcessor<'a, T>
where
    T: TokenStream<'a>,
{
    pub fn new(input: T) -> Self {
        Self {
            input,
            output_buffer: VecDeque::new(),
            input_buffer: VecDeque::new(),
            start_of_input: true,
            end_of_input: false,
            indentation: 0,
            tab_size: 4,
        }
    }

    /// Number of spaces in a tab.
    ///
    /// The default is `4`.
    pub fn tab_size(mut self, n: usize) -> Self {
        self.tab_size = n;
        self
    }

    fn push_comment(
        &mut self,
        comment_lines: Vec<Vec<u8>>,
        leading_newline: bool,
        trailing_newline: bool,
    ) {
        assert!(!comment_lines.is_empty());

        let comment = match (leading_newline, trailing_newline) {
            (true, true) => Token::BlockComment(comment_lines),
            (true, false) => Token::HeadComment(comment_lines),
            (false, true) => Token::TailComment(comment_lines),
            (false, false) => Token::InlineComment(comment_lines),
        };

        self.output_buffer.push_back(comment);

        if trailing_newline {
            self.output_buffer.push_back(Token::Newline);
        };
    }

    /// Process any pending tokens in the input buffer.
    ///
    /// The input buffer always contains a mixture of whitespaces, newlines
    /// comments, and control tokens. No other kind of tokens can appear in
    /// the input buffer. In fact, this function is called when a different
    /// kind of tokens is observed in the input stream, so, while processing
    /// the input buffer we can assume that the token that comes after those
    /// in the input buffer is not a whitespace, newline or comment.
    ///
    /// This function works like an automaton with two states `PreComment`
    /// and `Comment`. The automaton remains in the `PreComment` state
    /// while it processes any whitespaces and newlines that precede the
    /// comment. When it finds a [`Token::Comment`], it switches to the
    /// `Comment` state.
    fn process_input_buffer(&mut self) {
        // Start at PreComment state, `leading_newline` is initialized with
        // the value of `start_of_input` because comments that are at the
        // very beginning of a file are handled as if they were preceded by
        // a newline character.
        let mut state =
            State::PreComment { leading_newline: self.start_of_input };
        loop {
            match &mut state {
                State::PreComment { leading_newline } => {
                    match self.input_buffer.pop_front() {
                        Some(token @ Token::Whitespace) => {
                            self.indentation += 1;
                            self.output_buffer.push_back(token);
                        }
                        Some(token @ Token::Tab) => {
                            self.indentation += self.tab_size;
                            self.output_buffer.push_back(token);
                        }
                        // A newline has been found while in PreComment state,
                        // set the state's leading_newline to true.
                        Some(token @ Token::Newline) => {
                            self.indentation = 0;
                            self.output_buffer.push_back(token);
                            *leading_newline = true;
                        }
                        // A comment was found while in PreComment state, move
                        // to a new Comment state.
                        Some(ref token @ Token::Comment(comment)) => {
                            state = State::Comment {
                                indentation: self.indentation,
                                leading_newline: *leading_newline,
                                trailing_newline: false,
                                lines: split_comment_lines(
                                    comment,
                                    self.indentation,
                                    self.tab_size,
                                ),
                            };
                            self.indentation += token.len();
                        }
                        // Control tokens are passed directly to the output.
                        Some(token) => {
                            self.output_buffer.push_back(token);
                        }
                        None => break,
                    }
                }
                State::Comment {
                    lines,
                    trailing_newline,
                    leading_newline,
                    indentation,
                } => match self.input_buffer.pop_front() {
                    Some(Token::Whitespace) => {
                        self.indentation += 1;
                    }
                    Some(Token::Tab) => {
                        self.indentation += self.tab_size;
                    }
                    // Newline found while in the Comment state. If this is the
                    // first newline after the comment, the trailing_newline
                    // field in the current comment is set to true. However,
                    // if trailing_newline was already true this is the second
                    // newline after the comment, and in that case we push the
                    // current comment and go to the PreComment state.
                    //
                    // This means that an empty line in between comments break
                    // the comment block in two. For example:
                    //
                    // ```
                    // // This is a comment block.
                    // // These three lines are
                    // // put in the same BlockComment.
                    //
                    // // However, this other block is separated from
                    // // the previous one by an empty line, therefore
                    // // it goes to a different BlockComment.
                    // ```
                    //
                    Some(Token::Newline) => {
                        if *trailing_newline {
                            self.push_comment(
                                (*lines).to_vec(),
                                *leading_newline,
                                *trailing_newline,
                            );
                            self.output_buffer.push_back(Token::Newline);
                            state = State::PreComment { leading_newline: true }
                        } else {
                            *trailing_newline = true;
                        };
                        self.indentation = 0;
                    }
                    // Comment token found while in the Comment state. If the
                    // token's indentation matches the indentation of the
                    // current comment it is considered part of the same block.
                    //
                    // Example:
                    // ```
                    //      // This line, and the following one are part of
                    //      // the same block because they are aligned.
                    //
                    //      // This line is an independent comment.
                    //          // This line is independent comment.
                    // ```
                    Some(Token::Comment(comment)) => {
                        if *indentation == self.indentation {
                            lines.append(
                                split_comment_lines(
                                    comment,
                                    *indentation,
                                    self.tab_size,
                                )
                                .as_mut(),
                            );
                            *trailing_newline = false;
                        } else {
                            self.push_comment(
                                (*lines).to_vec(),
                                *leading_newline,
                                *trailing_newline,
                            );
                            state = State::Comment {
                                indentation: self.indentation,
                                leading_newline: *trailing_newline,
                                trailing_newline: false,
                                lines: split_comment_lines(
                                    comment,
                                    self.indentation,
                                    self.tab_size,
                                ),
                            };
                        }
                    }
                    // Control tokens are moved directly to the output.
                    Some(token) => {
                        self.output_buffer.push_back(token);
                    }
                    None => {
                        self.push_comment(
                            (*lines).to_vec(),
                            *leading_newline,
                            *trailing_newline || self.end_of_input,
                        );
                        break;
                    }
                },
            }
        }
    }
}

impl<'a, T> Iterator for CommentProcessor<'a, T>
where
    T: TokenStream<'a>,
{
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If there's some token in the output buffer, return it
            if let Some(token) = self.output_buffer.pop_front() {
                return Some(token);
            }

            // No tokens in the output buffer, take a token from the input.
            match self.input.next() {
                Some(token)
                    if token
                        .is(*NEWLINE | *WHITESPACE | *COMMENT | *CONTROL) =>
                {
                    // If the token from input is a newline, space or comment,
                    // put it in the input buffer.
                    self.input_buffer.push_back(token);
                }
                Some(token) => {
                    // If the token from the input is not a newline, space or
                    // comment the input buffer is processed, putting some
                    // tokens in the output buffer.
                    self.process_input_buffer();
                    self.start_of_input = false;
                    self.indentation += token.len();
                    self.output_buffer.push_back(token);
                }
                None if !self.input_buffer.is_empty() => {
                    // No more tokens in the input stream, but the input buffer
                    // contains some tokens, process them.
                    self.end_of_input = true;
                    self.process_input_buffer();
                }
                None => {
                    // No more tokens in the input stream and the input buffer
                    // is empty, nothing else to do.
                    return None;
                }
            }
        }
    }
}

/// Splits a multi-line comment into lines.
///
/// Also removes the specified number of whitespaces from the beginning of
/// each line.
///
/// This is necessary because when a multi-line comment that uses the
/// `/* comment */` syntax is indented, the comment itself contains some spaces
/// that are actually part of the indentation. For example:
///
/// ```text
/// <-- indentation -->/*
/// <-- indentation -->    This comment is indented
/// <-- indentation -->*/
/// ```
///
/// Notice how the comment contains some spaces (here represented by
/// `<-- indentation -->`) that should be removed/adjusted when the comment
/// is re-indented.
fn split_comment_lines(
    comment: &[u8],
    indentation: usize,
    tab_size: usize,
) -> Vec<Vec<u8>> {
    let comment = BStr::new(comment);
    let mut result = Vec::new();
    for line in comment.lines() {
        let mut i = 0;
        let mut comment_start = 0;
        for (start, _, ch) in line.char_indices() {
            if i >= indentation {
                comment_start = start;
                break;
            }
            match ch {
                ' ' => i += 1,
                '\t' => i += tab_size,
                _ => {
                    comment_start = start;
                    break;
                }
            }
        }
        result.push(line.get(comment_start..).unwrap_or_default().to_vec());
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::comments::CommentProcessor;
    use crate::tokens::Token;
    use pretty_assertions::assert_eq;
    use yara_x_parser::cst::SyntaxKind::SOURCE_FILE;

    fn test(input: Vec<Token>, expected_output: Vec<Token>) {
        assert_eq!(
            expected_output,
            CommentProcessor::new(input.into_iter()).collect::<Vec<Token>>()
        );
    }

    #[test]
    fn tests() {
        test(
            vec![Token::Comment(b"// some comment")],
            vec![
                Token::BlockComment(vec![b"// some comment".to_vec()]),
                Token::Newline,
            ],
        );

        test(
            vec![
                Token::Comment(b"// some comment"),
                Token::Newline,
                Token::Whitespace,
                Token::Comment(b"// some other comment"),
            ],
            vec![
                Token::BlockComment(vec![b"// some comment".to_vec()]),
                Token::Newline,
                Token::BlockComment(vec![b"// some other comment".to_vec()]),
                Token::Newline,
            ],
        );

        test(
            vec![
                Token::Whitespace,
                Token::Comment(b"// some comment"),
                Token::Newline,
                Token::Whitespace,
                Token::Comment(b"// some other comment"),
            ],
            vec![
                Token::Whitespace,
                Token::BlockComment(vec![
                    b"// some comment".to_vec(),
                    b"// some other comment".to_vec(),
                ]),
                Token::Newline,
            ],
        );

        test(
            vec![
                Token::Comment(b"// some comment"),
                Token::Newline,
                Token::Newline,
                Token::Comment(b"// some other comment"),
            ],
            vec![
                Token::BlockComment(vec![b"// some comment".to_vec()]),
                Token::Newline,
                Token::Newline,
                Token::BlockComment(vec![b"// some other comment".to_vec()]),
                Token::Newline,
            ],
        );

        test(
            vec![
                Token::Identifier(b"foo"),
                Token::Whitespace,
                Token::Comment(b"// some comment"),
                Token::Newline,
                Token::Comment(b"// some other comment"),
            ],
            vec![
                Token::Identifier(b"foo"),
                Token::Whitespace,
                Token::TailComment(vec![b"// some comment".to_vec()]),
                Token::Newline,
                Token::BlockComment(vec![b"// some other comment".to_vec()]),
                Token::Newline,
            ],
        );

        test(
            vec![
                Token::Identifier(b"foo"),
                Token::Whitespace,
                Token::Comment(b"// some comment"),
                Token::Newline,
                Token::Whitespace,
                Token::Whitespace,
                Token::Whitespace,
                Token::Whitespace,
                Token::Comment(b"// some other comment"),
            ],
            vec![
                Token::Identifier(b"foo"),
                Token::Whitespace,
                Token::TailComment(vec![
                    b"// some comment".to_vec(),
                    b"// some other comment".to_vec(),
                ]),
                Token::Newline,
            ],
        );

        test(
            vec![
                Token::Identifier(b"foo"),
                Token::Whitespace,
                Token::Comment(b"/* some comment */"),
                Token::Whitespace,
                Token::Identifier(b"foo"),
            ],
            vec![
                Token::Identifier(b"foo"),
                Token::Whitespace,
                Token::InlineComment(vec![b"/* some comment */".to_vec()]),
                Token::Identifier(b"foo"),
            ],
        );

        test(
            vec![
                Token::Begin(SOURCE_FILE),
                Token::Comment(b"// comment 1"),
                Token::Newline,
                Token::Newline,
                Token::Comment(b"// comment 2"),
                Token::Newline,
                Token::Whitespace,
                Token::Whitespace,
                Token::End(SOURCE_FILE),
            ],
            vec![
                Token::Begin(SOURCE_FILE),
                Token::BlockComment(vec![b"// comment 1".to_vec()]),
                Token::Newline,
                Token::Newline,
                Token::End(SOURCE_FILE),
                Token::BlockComment(vec![b"// comment 2".to_vec()]),
                Token::Newline,
            ],
        );
    }
}
