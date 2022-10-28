use std::collections::VecDeque;

use crate::formatter::tokens::{Token, TokenStream};

pub(crate) struct CommentProcessor<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    input_buffer: VecDeque<Token<'a>>,
    output_buffer: VecDeque<Token<'a>>,
    heading_newline: bool,
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
            // heading_newline is initially true because the start of the token
            // stream is treated as a newline. If the first token in the stream
            // is a comment, it should be treated as if was preceded by a
            // newline
            heading_newline: true,
        }
    }

    fn process_input_buffer(&mut self, end_of_input: bool) {
        for (i, token) in self.input_buffer.iter().enumerate() {
            if let Token::Comment(comment) = token {
                // Is this comment preceded by a newline? If the comment is the
                // first token in the input buffer, we rely on the value of
                // self.heading_newline, which indicates if the token immediately
                // before the first one in input buffer was a newline or not.
                let heading_newline = if i > 0 {
                    if let Some(token) = self.input_buffer.get(i - 1) {
                        matches!(token, Token::Newline)
                    } else {
                        self.heading_newline
                    }
                } else {
                    self.heading_newline
                };

                // Is this comment followed by a newline? If the comment is the
                // the last token in the input buffer, we rely on the value of
                // end_of_input, which indicates if there is some token after
                // the ones in the input buffer. If end_of_input is true, we
                // treat it as if the input finishes with a trailing newline.
                // If it's false, the pending tokens can't be newlines and
                // therefore trailing_newline is false.
                let tailing_newline =
                    if let Some(token) = self.input_buffer.get(i + 1) {
                        matches!(token, Token::Newline)
                    } else {
                        end_of_input
                    };

                // Create the appropriate type of comment depending on whether
                // it is preceded and/or followed by a newline.
                let comment = match (heading_newline, tailing_newline) {
                    (true, true) => {
                        Token::BlockComment((*comment).to_string())
                    }
                    (true, false) => {
                        Token::HeadComment((*comment).to_string())
                    }
                    (false, true) => {
                        Token::TailComment((*comment).to_string())
                    }
                    (false, false) => {
                        Token::InlineComment((*comment).to_string())
                    }
                };

                self.output_buffer.push_back(comment);
            }
        }

        self.input_buffer.clear()
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
            if let Some(token) = self.input.next() {
                match token {
                    // If the token from input is a newline or comment, put it
                    // in the input buffer.
                    Token::Newline | Token::Comment(_) => {
                        self.input_buffer.push_back(token)
                    }
                    // If the token from the input is not a newline or comment
                    // the input buffer is processed, putting some tokens in
                    // the output buffer.
                    _ => {
                        self.process_input_buffer(false);
                        self.output_buffer.push_back(token);
                        self.heading_newline = false;
                    }
                }
            } else if !self.input_buffer.is_empty() {
                // No more tokens in the input but, but the input buffer
                // contains some tokens, process them.
                self.process_input_buffer(true);
            } else {
                // No more tokens in the input and the input buffer is empty,
                // nothing else to do.
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::formatter::comments::CommentProcessor;
    use crate::formatter::tokens::Token;

    #[test]
    fn test1() {
        let input = vec![Token::Comment("// some comment")];

        let output =
            CommentProcessor::new(input.into_iter()).collect::<Vec<Token>>();

        assert_eq!(
            output,
            vec![Token::BlockComment("// some comment".to_string())]
        )
    }

    #[test]
    fn test2() {
        let input = vec![
            Token::Comment("// some comment"),
            Token::Comment("// some other comment"),
        ];

        let output =
            CommentProcessor::new(input.into_iter()).collect::<Vec<Token>>();

        assert_eq!(
            output,
            vec![
                Token::HeadComment("// some comment".to_string()),
                Token::TailComment("// some other comment".to_string()),
            ]
        )
    }

    #[test]
    fn test3() {
        let input = vec![
            Token::Comment("// some comment"),
            Token::Newline,
            Token::Comment("// some other comment"),
        ];

        let output =
            CommentProcessor::new(input.into_iter()).collect::<Vec<Token>>();

        assert_eq!(
            output,
            vec![
                Token::BlockComment("// some comment".to_string()),
                Token::BlockComment("// some other comment".to_string()),
            ]
        )
    }
}
