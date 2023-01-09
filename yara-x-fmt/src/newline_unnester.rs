use crate::{Token, TokenStream};
use std::collections::VecDeque;

/// Climber is a processor that moves whitespaces and newlines to the
/// outermost grammar rule.
///
/// In the sequence of tokens obtained from [`crate::tokens::Tokens`], newline
/// and whitespace tokens often appear at "unnatural" places, making difficult
/// to create processor rules that work with these kinds of tokens.
///
/// For example, suppose that we have the following YARA rule:
///
/// ```text
/// rule test {
///   strings:
///     $foo = "foo" wide
///     $bar = "bar
///   condition:
///     all of them
/// }
/// ```
///
/// In the tokens produced for that rule we can find the following sequence
/// (some tokens have removed for simplicity and indentation has been added
/// for illustrating highlighting the Begin/End blocks.
///
/// Begin(pattern_def),
///     Identifier("$a"),
///     Whitespace,
///     Punctuation("="),
///     Whitespace,
///     Literal("\"foo\""),
///     Whitespace,
///     Begin(pattern_mods),
///         Keyword("wide"),
///         Whitespace,             
///         Newline,                <--- Why is the Newline here?
///         Whitespace,             
///         ... more whitespaces
///     End(pattern_mods),
/// End(pattern_def),
/// Begin(pattern_def),
/// Identifier("$b"),
/// ... more tokens
///
/// Notice how the the Newline and Whitespace tokens that follow after the
/// `wide` keyword are considered part of the `pattern_mods` grammar rule.
/// This feels unnatural because that newline character is actually separating
/// the the two pattern definitions, `$foo` and `$bar`. When creating rules
/// that checks for the existence of newlines characters in-between pattern
/// definitions, the fact that this newline character is buried deep inside
/// the `pattern_mods` rule makes things a lot of harder.
///
/// This other sequence feels more much natural and it's easier to work with:
///
/// Begin(pattern_def),
///     Identifier("$a"),
///     Whitespace,
///     Punctuation("="),
///     Whitespace,
///     Literal("\"foo\""),
///     Whitespace,
///     Begin(pattern_mods),
///         Keyword("wide"),
///     End(pattern_mods),
/// End(pattern_def),
/// Whitespace,             
/// Newline,    <--- Now the newline is in-between the `pattern_def` rules
/// Whitespace,             
/// ... more whitespaces
/// Begin(pattern_def),
/// Identifier("$b"),
/// ... more tokens
///
/// That's exactly what this processor does. It displaces newline and whitespace
/// tokens that appear at the end of some inner grammar rule to the outermost
/// possible rule, which is the place where it usually feels right.
pub(crate) struct NewlineUnnester<'a, T>
where
    T: TokenStream<'a>,
{
    input: T,
    input_buffer: VecDeque<Token<'a>>,
    output_buffer: VecDeque<Token<'a>>,
}

impl<'a, T> NewlineUnnester<'a, T>
where
    T: TokenStream<'a>,
{
    pub fn new(input: T) -> Self {
        Self {
            input,
            input_buffer: VecDeque::new(),
            output_buffer: VecDeque::new(),
        }
    }
}

impl<'a, T> Iterator for NewlineUnnester<'a, T>
where
    T: TokenStream<'a>,
{
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // If there's some token in the output buffer, return it.
        if let Some(token) = self.output_buffer.pop_front() {
            return Some(token);
        }
        for token in self.input.by_ref() {
            match token {
                // Whitespaces and newlines are copied to input_buffer
                Token::Whitespace | Token::Newline => {
                    self.input_buffer.push_back(token);
                }
                // Token::End skips over whitespace and newlines accumulated in
                // input_buffer, and go directly to output_buffer
                Token::End(_) => {
                    self.output_buffer.push_back(token);
                    return self.output_buffer.pop_front();
                }
                // Any other token causes a flush of input_buffer, copying all
                // its items to output buffer.
                _ => {
                    self.input_buffer.push_back(token);
                    for token in self.input_buffer.drain(0..) {
                        self.output_buffer.push_back(token)
                    }
                    return self.output_buffer.pop_front();
                }
            }
        }
        // When this point is reached there's nothing in output_buffer
        // and no more input, move anything remaining in input_buffer
        // to output_buffer.
        for token in self.input_buffer.drain(0..) {
            self.output_buffer.push_back(token)
        }
        self.output_buffer.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use crate::newline_unnester::NewlineUnnester;
    use crate::tokens::Token;
    use pretty_assertions::assert_eq;
    use yara_x_parser::GrammarRule;

    #[test]
    fn test1() {
        let input = vec![
            Token::Begin(GrammarRule::rule_tags),
            Token::Identifier("foo"),
            Token::Whitespace,
            Token::Whitespace,
            Token::Newline,
            Token::End(GrammarRule::rule_tags),
            Token::Newline,
            Token::End(GrammarRule::rule_decl),
            Token::Whitespace,
            Token::Newline,
        ];

        let output =
            NewlineUnnester::new(input.into_iter()).collect::<Vec<Token>>();

        assert_eq!(
            output,
            vec![
                Token::Begin(GrammarRule::rule_tags),
                Token::Identifier("foo"),
                Token::End(GrammarRule::rule_tags),
                Token::End(GrammarRule::rule_decl),
                Token::Whitespace,
                Token::Whitespace,
                Token::Newline,
                Token::Newline,
                Token::Whitespace,
                Token::Newline,
            ]
        )
    }
}
