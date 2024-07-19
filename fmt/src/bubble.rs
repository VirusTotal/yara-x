/*! A processor that allows reordering some tokens with respect to others.

The name for this module comes from the metaphor of a bubble of a lower
density substance (e.g: air) in a medium of higher density substance (e.g:
water). In this case we have a certain class of tokens that must "ascend"
when they are in a medium composed of another class of tokens. In this
context "ascending" means going left in the sequence of tokens.

For example, suppose that we have three types of tokens `A`, `B` and `C` in
the following sequence:

A1, A2, B1, B2, B2, B3, C1, B4, C2, A3, A4, C3

If we say that tokens of type `C` are air, and tokens of type `B` are water,
the resulting sequence will be:

A1, A2, C1, C2, B1, B2, B2, B3, B4, A3, A4, C3

Tokens of type `C` (air) will move in front of all tokens of type `B` (water),
while maintaining their relative orders. Notice however that tokens of type `A`
are neither air nor water, so they act as a barrier that impedes further
movement of `C` tokens.

# What is this used for?

There are multiple scenarios in which this abstraction is useful for reordering
tokens. For example, [`crate::tokens::Tokens`], returns a sequence of tokens in
which newlines often appear at "unnatural" places, making difficult to create
processor rules that work with these kinds of tokens.

Consider the following YARA rule:

```text
rule test {
  strings:
    $foo = "foo" wide
    $bar = "bar
  condition:
    all of them
}
```

In the tokens produced for that rule we can find the following sequence
(some tokens have removed for simplicity and indentation has been added
for illustrating highlighting the Begin/End blocks.

Begin(pattern_def),
    Identifier("$a"),
    Punctuation("="),
    Literal("\"foo\""),
    Begin(pattern_mods),
        Keyword("wide"),
        Newline,                <--- Why is the Newline here?
    End(pattern_mods),
End(pattern_def),
Begin(pattern_def),
Identifier("$b"),
... more tokens

Notice how the newline tokens that follow after the `wide` keyword is
considered part of the `pattern_mods` grammar rule. This feels unnatural
because that newline character is actually separating the two pattern
definitions, `$foo` and `$bar`. When creating rules that checks for the
existence of newlines characters in-between pattern definitions, the fact
that this newline character is buried deep inside the `pattern_mods` rule
makes things a lot of harder.

This other sequence feels more much natural, and it's easier to work with:

Begin(pattern_def),
    Identifier("$a"),
    Punctuation("="),
    Literal("\"foo\""),
    Begin(pattern_mods),
        Keyword("wide"),
    End(pattern_mods),
End(pattern_def),
Newline,    <--- Now the newline is in-between the `pattern_def` rules
Begin(pattern_def),
Identifier("$b"),
... more tokens

The [`crate::bubble::Bubble`] processor fixes this issue by moving the
End(..) tokens to the left while displacing newlines to the right.
*/

use crate::{Token, TokenStream};
use std::collections::VecDeque;

/// A pipeline that makes a certain class of token ascend over another class.
pub(crate) struct Bubble<'a, T, A, W>
where
    T: TokenStream<'a>,
    A: Fn(&Token) -> bool,
    W: Fn(&Token) -> bool,
{
    input: T,
    is_air: A,
    is_water: W,
    input_buffer: VecDeque<Token<'a>>,
    output_buffer: VecDeque<Token<'a>>,
}

impl<'a, T, A, W> Bubble<'a, T, A, W>
where
    T: TokenStream<'a>,
    A: Fn(&Token) -> bool,
    W: Fn(&Token) -> bool,
{
    /// Creates a new instance of [`Bubble`].
    ///
    /// `is_air` and `is_water` are functions that receive a reference to
    /// a token and return a boolean, indicating if the token is considered
    /// "air" or "water" respectively.
    ///
    /// # Panics
    ///
    /// If the same token is considered "air" and "water" simultaneously.
    /// The "air" and "water" classes must be exclusive.
    pub fn new(input: T, is_air: A, is_water: W) -> Self {
        Self {
            input,
            is_air,
            is_water,
            input_buffer: VecDeque::new(),
            output_buffer: VecDeque::new(),
        }
    }
}

impl<'a, T, A, W> Iterator for Bubble<'a, T, A, W>
where
    T: TokenStream<'a>,
    A: Fn(&Token) -> bool,
    W: Fn(&Token) -> bool,
{
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // If there's some token in the output buffer, return it.
        if let Some(token) = self.output_buffer.pop_front() {
            return Some(token);
        }
        for token in self.input.by_ref() {
            let is_air = (self.is_air)(&token);
            let is_water = (self.is_water)(&token);
            if is_air && is_water {
                panic!("token {:?} is both air and water", token)
            }
            if is_water {
                self.input_buffer.push_back(token);
            } else if is_air {
                self.output_buffer.push_back(token);
                return self.output_buffer.pop_front();
            } else {
                self.output_buffer.append(&mut self.input_buffer);
                self.output_buffer.push_back(token);
                return self.output_buffer.pop_front();
            }
        }
        // When this point is reached there's nothing in output_buffer
        // and no more input, move anything remaining in input_buffer
        // to output_buffer.
        self.output_buffer.append(&mut self.input_buffer);
        self.output_buffer.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use crate::bubble::Bubble;
    use crate::tokens::Token;
    use crate::{NEWLINE, WHITESPACE};
    use pretty_assertions::assert_eq;
    use yara_x_parser::cst::SyntaxKind;

    #[test]
    fn test_nest() {
        let input = vec![
            Token::Begin(SyntaxKind::RULE_TAGS),
            Token::Identifier(b"foo"),
            Token::Whitespace,
            Token::Whitespace,
            Token::Newline,
            Token::End(SyntaxKind::RULE_TAGS),
            Token::Newline,
            Token::End(SyntaxKind::RULE_DECL),
            Token::Whitespace,
            Token::Newline,
        ];

        let output = Bubble::new(
            input.into_iter(),
            |token| token.is(*NEWLINE | *WHITESPACE),
            |token| matches!(token, Token::End(_)),
        )
        .collect::<Vec<Token>>();

        assert_eq!(
            output,
            vec![
                Token::Begin(SyntaxKind::RULE_TAGS),
                Token::Identifier(b"foo"),
                Token::Whitespace,
                Token::Whitespace,
                Token::Newline,
                Token::Newline,
                Token::Whitespace,
                Token::Newline,
                Token::End(SyntaxKind::RULE_TAGS),
                Token::End(SyntaxKind::RULE_DECL),
            ]
        )
    }

    #[test]
    fn test_unnest() {
        let input = vec![
            Token::Begin(SyntaxKind::RULE_TAGS),
            Token::Identifier(b"foo"),
            Token::Whitespace,
            Token::Whitespace,
            Token::Newline,
            Token::End(SyntaxKind::RULE_TAGS),
            Token::Newline,
            Token::End(SyntaxKind::RULE_DECL),
            Token::Whitespace,
            Token::Newline,
        ];

        let output = Bubble::new(
            input.into_iter(),
            |token| matches!(token, Token::End(_)),
            |token| token.is(*NEWLINE | *WHITESPACE),
        )
        .collect::<Vec<Token>>();

        assert_eq!(
            output,
            vec![
                Token::Begin(SyntaxKind::RULE_TAGS),
                Token::Identifier(b"foo"),
                Token::End(SyntaxKind::RULE_TAGS),
                Token::End(SyntaxKind::RULE_DECL),
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
