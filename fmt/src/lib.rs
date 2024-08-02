/*! A code formatter for YARA rules

This crate implements a code format for YARA in the spirit of other tools like
`rustfmt` and `gofmt`.

# Usage

```no_run
# use std::fs::File;
use yara_x_fmt::Formatter;

let input = File::open("original.yar").unwrap();
let output = File::create("formatted.yar").unwrap();

Formatter::new().format(input, output).unwrap();
```
*/
use std::io;

use thiserror::Error;

use tokens::Token::*;
use tokens::TokenStream;
use yara_x_parser::cst::SyntaxKind;
use yara_x_parser::Parser;

use crate::align::Align;
use crate::tokens::categories::*;
use crate::tokens::*;

mod align;
mod bubble;
mod comments;
mod indentation;
mod processor;
mod tokens;
mod trailing_spaces;

#[cfg(test)]
mod tests;

/// Errors returned by [`Formatter::format`].
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// Error while reading from input.
    #[error("Read error")]
    ReadError(io::Error),

    /// Error while writing to output.
    #[error("Write error")]
    WriteError(io::Error),
    // TODO
    // Error while parsing the input.
    //#[error("Parse error")]
    //ParseError(#[from] yara_x_parser::Error),
}

/// Formats YARA source code automatically.
pub struct Formatter {}

impl Default for Formatter {
    fn default() -> Self {
        Self::new()
    }
}

// Formatter public API.
impl Formatter {
    /// Creates a new formatter.
    pub fn new() -> Self {
        Formatter {}
    }

    /// Reads YARA source code from `input` and write it into `output` after
    /// formatting.
    ///
    /// This function will fail if it can't read from the input, write to the
    /// output, or when the input doesn't contain syntactically valid YARA
    /// rules.
    /// TODO: syntactically invalid rules may be formatted
    pub fn format<R, W>(&self, mut input: R, output: W) -> Result<(), Error>
    where
        R: io::Read,
        W: io::Write,
    {
        let mut buf = Vec::new();

        // Read the source code from input and store it in buf.
        input.read_to_end(&mut buf).map_err(Error::ReadError)?;

        let stream = Parser::new(buf.as_slice()).into_cst_stream();
        let tokens = Tokens::new(stream);

        Formatter::formatter(tokens)
            .write_to(output)
            .map_err(Error::WriteError)
    }
}

// Private API for formatter.
impl Formatter {
    fn formatter<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        let tokens = comments::CommentProcessor::new(input);

        // Remove all whitespaces from the original source.
        let tokens = processor::Processor::new(tokens).add_rule(
            |ctx| ctx.token(1).is(*WHITESPACE),
            processor::actions::drop,
        );

        // Displace tail comments and newlines up with respect to tokens that
        // indicate the start and end of a grammar rule. This effectively moves
        // such comments and newlines to the innermost grammar rule preceding
        // them. For example, suppose that we have the following rule:
        //
        //   import "test"  // Comment
        //
        //   rule test {
        //     strings:
        //       $a = "foo"
        //     condition:
        //       true
        //   }
        //
        // The sequence of tokens produced for that rule looks like:
        //
        //   Begin(SOURCE_FILE)
        //   Begin(IMPORT_STMT)
        //   Keyword("import")
        //   Literal("tests")
        //   End(IMPORT_STMT)
        //   Begin(RULE_DECL)
        //   TailComment("// Comment")
        //   Newline
        //   Keyword("rule")
        //   .... more
        //
        // Notice how TailComment("// Comment") and the Newline that follows
        // are placed just before the "rule" keyword, and inside the rule_decl
        // grammar rule. This is not the most natural place for this tail comment,
        // its natural place is just after the "tests" literal, like this:
        //
        //   Begin(SOURCE_FILE)
        //   Begin(IMPORT_STMT)
        //   Keyword("import")
        //   Literal("tests")
        //   TailComment("// Comment")
        //   Newline
        //   End(IMPORT_STMT)
        //   Begin(RULE_DECL)
        //   Keyword("rule")
        //   .... more
        //
        // That's exactly what the Bubble pipeline does. See the documentation for
        // the `bubble` module for more details.
        let tokens = bubble::Bubble::new(
            tokens,
            |token| {
                matches!(token, Token::TailComment(_)) || token.is(*NEWLINE)
            },
            |token| matches!(token, Token::Begin(_) | Token::End(_)),
        );

        // Displace newlines down with respect to tokens that indicate end of a
        // grammar rule. This effectively moves them to the outermost grammar
        // rule. See the documentation for the `bubble` module for more details.
        let tokens = bubble::Bubble::new(
            tokens,
            |token| matches!(token, Token::End(_)),
            |token| token.is(*NEWLINE),
        );

        // Remove newlines in multiple cases.
        let tokens = processor::Processor::new(tokens)
            // Remove all newlines at the beginning of the file. When the
            // processor is at the beginning of the file token(-1) is None.
            // Notice that this works because all these newlines have been
            // moved up and placed Token::Begin(source_file) by the first
            // bubble pipeline.
            .add_rule(
                |ctx| ctx.token(-1).eq(&None) && ctx.token(1).is(*NEWLINE),
                processor::actions::drop,
            )
            // Remove excess of consecutive newlines, only two consecutive
            // newlines are allowed.
            .add_rule(
                |ctx| {
                    ctx.token(-2).is(*NEWLINE)
                        && ctx.token(-1).is(*NEWLINE)
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines between rule tags and between rule modifiers.
            .add_rule(
                |ctx| {
                    (ctx.in_rule(SyntaxKind::RULE_MODS, false)
                        || ctx.in_rule(SyntaxKind::RULE_TAGS, false))
                        && ctx.token(-1).is_not(*COMMENT)
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after rule modifiers.
            .add_rule(
                |ctx| {
                    ctx.token(-1).eq(&End(SyntaxKind::RULE_MODS))
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after rule tags
            .add_rule(
                |ctx| {
                    ctx.token(-1).eq(&End(SyntaxKind::RULE_TAGS))
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after "meta:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::META_BLK, false)
                        && ctx.token(-1).eq(&COLON)
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after "strings:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::PATTERNS_BLK, false)
                        && ctx.token(-1).eq(&COLON)
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            );

        let tokens = processor::Processor::new(tokens)
            //
            // Insert newline in front of import statements, making sure that
            // each import starts at a new line. The newline is not inserted if
            // the statement is at the start of the file.
            //
            // Example:
            //
            // import "foo" import "bar"
            //
            // Inserts newline before import "bar".
            //
            .add_rule(
                |ctx| {
                    let next_token = ctx.token(1);
                    let prev_token = ctx.token(-1);

                    next_token.eq(&Begin(SyntaxKind::IMPORT_STMT))
                        && prev_token.neq(&Begin(SyntaxKind::SOURCE_FILE))
                        && prev_token.is_not(*NEWLINE)
                },
                processor::actions::newline,
            )
            //
            // Insert newline in front of rule declarations, making sure that
            // rule declarations starts at a new line. The newline is not
            // inserted if the rule is at the start of the file.
            //
            // Example:
            //
            // rule foo { ... } rule bar { ... }
            //
            // Inserts newline before "rule bar".
            //
            .add_rule(
                |ctx| {
                    let next_token = ctx.token(1);
                    let prev_token = ctx.token(-1);

                    next_token.eq(&Begin(SyntaxKind::RULE_DECL))
                        && prev_token.neq(&Begin(SyntaxKind::SOURCE_FILE))
                        && prev_token.is_not(*NEWLINE)
                },
                processor::actions::newline,
            )
            //
            // Insert additional newline in front of a rule declaration that
            // already starts at a newline, but only if not preceded by a
            // comment. In other words, this adds empty lines in between rule
            // declarations, but don't do it if the rule is preceded by a
            // comment.
            //
            // Example:
            //
            //  rule foo {
            //    ...
            //  }
            //  rule bar {
            //    ...
            //  }
            //
            // Inserts newline before "rule bar".
            //
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&Begin(SyntaxKind::RULE_DECL))
                        && ctx.token(-1).is(*NEWLINE)
                        && ctx.token(-2).is_not(*NEWLINE | *COMMENT)
                },
                processor::actions::newline,
            )
            //
            //
            // Insert empty line at the end of the file
            //
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&End(SyntaxKind::SOURCE_FILE))
                        && ctx.token(-1).is_not(*NEWLINE)
                        && ctx.token(2).is_not(*NEWLINE)
                },
                processor::actions::newline,
            );

        let tokens = processor::Processor::new(tokens)
            .set_passthrough(*CONTROL)
            // Add newline in front of "meta", "strings" and "condition"
            .add_rule(
                |ctx| {
                    matches!(
                        ctx.token(1),
                        Keyword(b"meta")
                            | Keyword(b"strings")
                            | Keyword(b"condition")
                    ) && ctx.token(-1).is_not(*NEWLINE)
                },
                processor::actions::newline,
            )
            // Add newline after "meta:", "strings:" and "condition:".
            .add_rule(
                |ctx| {
                    ctx.token(1).is_not(*NEWLINE)
                        && ctx.token(-1).eq(&COLON)
                        && matches!(
                            ctx.token(-2),
                            Keyword(b"meta")
                                | Keyword(b"strings")
                                | Keyword(b"condition")
                        )
                },
                processor::actions::newline,
            )
            // Add newline in front of pattern identifiers in the "strings"
            // section.
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::PATTERN_DEF, false)
                        && ctx.token(1).is(*IDENTIFIER)
                        && ctx.token(-1).is_not(*NEWLINE)
                },
                processor::actions::newline,
            )
            // Add newline before the closing brace at the end of rule.
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::RULE_DECL, false)
                        && ctx.token(1).eq(&RBRACE)
                        && ctx.token(-1).is_not(*NEWLINE)
                },
                processor::actions::newline,
            );

        let tokens = Self::indent_body(tokens);
        let tokens = Self::indent_sections(tokens);
        let tokens = Self::indent_parenthesized_exprs(tokens);

        // indent_body and indent_sections will insert Indentation tokens, but
        // won't take into account that those tokens must appear before the
        // newline they are expected to affect. This fixes the issue by moving
        // indentation tokens in front of newline tokens if they appear in
        // reverse order.
        let tokens = bubble::Bubble::new(
            tokens,
            |token| matches!(token, Indentation(_)),
            |token| token.is(*NEWLINE),
        );

        // Make sure that tail and block comments are followed by newline. In
        // most cases this is already the case, but some of the rules that
        // remove newlines may remove those appearing after the comment.
        let tokens = processor::Processor::new(tokens)
            .set_passthrough(*CONTROL)
            .add_rule(
                |ctx| {
                    matches!(ctx.token(-1), TailComment(_) | BlockComment(_))
                        && ctx.token(1).is_not(*NEWLINE)
                },
                processor::actions::newline,
            );

        let tokens = Self::add_spacing(tokens);

        let tokens = Self::align_comments_in_hex_patterns(tokens);
        let tokens = Self::align_patterns(tokens);

        let tokens = indentation::AddIndentationSpaces::new(tokens);
        let tokens = trailing_spaces::RemoveTrailingSpaces::new(tokens);

        tokens
    }

    /// Indents the sections (meta, strings, condition) of a rule one level up.
    /// For example, for this input:
    ///
    /// rule foo {
    /// strings:
    /// $a = "foo"
    /// condition:
    /// true
    /// }
    ///
    /// ... the result is ...
    ///
    /// rule foo {
    /// strings:
    ///   $a = "foo"
    /// condition:
    ///   true
    /// }
    fn indent_sections<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        processor::Processor::new(input)
            // Ignore all comments
            .set_passthrough(*COMMENT)
            // Increase indentation after "condition:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::CONDITION_BLK, false)
                        && ctx.token(-1).eq(&COLON)
                },
                processor::actions::insert(Indentation(1)),
            )
            // Decrease indentation after the condition.
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&End(SyntaxKind::CONDITION_BLK))
                        && ctx.token(-1).neq(&Indentation(-1))
                },
                processor::actions::insert(Indentation(-1)),
            )
            // Increase indentation after "meta:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::META_BLK, false)
                        && ctx.token(-1).eq(&COLON)
                },
                processor::actions::insert(Indentation(1)),
            )
            // Decrease indentation after meta definitions
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&End(SyntaxKind::META_BLK))
                        && ctx.token(-1).neq(&Indentation(-1))
                },
                processor::actions::insert(Indentation(-1)),
            )
            // Increase indentation after "strings:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::PATTERNS_BLK, false)
                        && ctx.token(-1).eq(&COLON)
                },
                processor::actions::insert(Indentation(1)),
            )
            // Decrease indentation after pattern definitions.
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&End(SyntaxKind::PATTERNS_BLK))
                        && ctx.token(-1).neq(&Indentation(-1))
                },
                processor::actions::insert(Indentation(-1)),
            )
    }

    /// Indents the body of a rule. For this input...
    ///
    /// rule foo {
    /// strings:
    /// $a = "foo"
    /// condition:
    /// true
    /// }
    ///
    /// ... the result is ...
    ///
    /// rule foo {
    ///   strings:
    ///   $a = "foo"
    ///   condition:
    ///   true
    /// }
    ///
    fn indent_body<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        processor::Processor::new(input)
            // Ignore all comments.
            .set_passthrough(*COMMENT)
            // Increase indentation after the opening brace in a rule
            // declaration.
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::RULE_DECL, false)
                        && ctx.token(-1).eq(&LBRACE)
                },
                processor::actions::insert(Indentation(1)),
            )
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::RULE_DECL, false)
                        && ctx.token(1).eq(&RBRACE)
                        && ctx.token(-1).neq(&Indentation(-1))
                },
                processor::actions::insert(Indentation(-1)),
            )
    }

    /// Indent parenthesized expressions in rule conditions.
    ///
    /// rule foo {
    /// strings:
    ///   $a = "foo"
    ///   $b = "bar"
    /// condition:
    ///    (
    ///    $a and $b
    ///    )
    /// }
    ///
    /// ... the result is ...
    ///
    /// rule foo {
    /// strings:
    ///   $a = "foo"
    ///   $b = "bar"
    /// condition:
    ///    (
    ///      $a and $b
    ///    )
    /// }
    ///
    fn indent_parenthesized_exprs<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        processor::Processor::new(input)
            .set_passthrough(*COMMENT)
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::BOOLEAN_EXPR, true)
                        && ctx.token(-1).eq(&LPAREN)
                },
                processor::actions::insert(Indentation(1)),
            )
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::BOOLEAN_EXPR, true)
                        && ctx.token(1).eq(&RPAREN)
                        && ctx.token(-1).neq(&Indentation(-1))
                },
                processor::actions::insert(Indentation(-1)),
            )
    }

    /// Aligns the equals signs in pattern definitions. For example, for this
    /// input:
    ///
    /// ```text
    /// rule foo {
    ///   strings:
    ///     $short = "foo"
    ///     $very_long = "bar"
    ///     $even_longer = "baz"
    ///   condition:
    ///     true
    /// }
    /// ```
    ///
    /// ... the result is ...
    ///
    /// ```text
    /// rule foo {
    ///   strings:
    ///     $short       = "foo"
    ///     $very_long   = "bar"
    ///     $even_longer = "baz"
    ///   condition:
    ///     true
    /// }
    /// ```
    ///
    /// Pattern groups separated by empty lines are handled independently, for
    /// example:
    ///
    /// ```text
    /// rule foo {
    ///   strings:
    ///     $short     = "foo"
    ///     $very_long = "bar"
    ///
    ///     $even_longer    = "baz"
    ///     $longest_of_all = "qux"
    ///   condition:
    ///     true
    /// }
    /// ```
    ///
    /// The patterns in the first block are aligned together, but they are not
    /// influenced by the longer lines in the second block.
    ///
    /// The input must contain at least one newline character after each
    /// pattern definition.
    fn align_patterns<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        // First insert the alignment markers at the appropriate places...
        let input_with_markers = processor::Processor::new(input)
            // Insert `AlignmentBlockBegin` after the start of the pattern
            // definitions block.
            .add_rule(
                |ctx| ctx.token(-1).eq(&Begin(SyntaxKind::PATTERNS_BLK)),
                processor::actions::insert(AlignmentBlockBegin),
            )
            // Insert `AlignmentBlockEnd` just before the end of the pattern
            // definitions block.
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&End(SyntaxKind::PATTERNS_BLK))
                        && ctx.token(-1).neq(&AlignmentBlockEnd)
                },
                processor::actions::insert(AlignmentBlockEnd),
            )
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::PATTERNS_BLK, false)
                        && ctx.token(-2).eq(&Newline)
                        && ctx.token(-1).eq(&Newline)
                },
                |ctx| {
                    ctx.push_output_token(Some(AlignmentBlockEnd));
                    ctx.push_output_token(Some(AlignmentBlockBegin));
                },
            )
            // Insert `AlignmentMarker` before each equal sign in a pattern
            // definition.
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::PATTERN_DEF, false)
                        && ctx.token(1).eq(&EQUAL)
                        && ctx.token(-1).neq(&AlignmentMarker)
                },
                processor::actions::insert(AlignmentMarker),
            );

        // ... then pass the token stream with the markers to Aligner, which
        // returns a token stream that replaces the markers with the
        // appropriate number of spaces.
        Align::new(input_with_markers)
    }

    /// Aligns tail comments inside hex patterns
    ///
    /// rule foo {
    ///   strings:
    ///     $hex = {
    ///        00 01  // Lorem
    ///        00 01 02  // ipsum
    ///     }
    ///   condition:
    ///     true
    /// }
    ///
    /// ... the result is ...
    ///
    /// rule foo {
    ///   strings:
    ///     $hex = {
    ///        00 01     // Lorem
    ///        00 01 02  // ipsum
    ///     }
    ///   condition:
    ///     true
    /// }
    ///
    fn align_comments_in_hex_patterns<'a, I>(
        input: I,
    ) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        // First insert the alignment markers at the appropriate places...
        let input_with_markers = processor::Processor::new(input)
            .add_rule(
                |ctx| ctx.token(-1).eq(&Begin(SyntaxKind::HEX_PATTERN)),
                processor::actions::insert(AlignmentBlockBegin),
            )
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&End(SyntaxKind::HEX_PATTERN))
                        && ctx.token(-1).neq(&AlignmentBlockEnd)
                },
                processor::actions::insert(AlignmentBlockEnd),
            )
            .add_rule(
                |ctx| {
                    ctx.in_rule(SyntaxKind::HEX_PATTERN, true)
                        && matches!(ctx.token(1), Token::TailComment(_))
                        && ctx.token(-1).neq(&AlignmentMarker)
                },
                processor::actions::insert(AlignmentMarker),
            );

        // ... then pass the token stream with the markers to Aligner, which
        // returns a token stream that replaces the markers with the
        // appropriate number of spaces.
        Align::new(input_with_markers)
    }

    fn add_spacing<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        processor::Processor::new(input)
            // Ignore all control tokens.
            .set_passthrough(*CONTROL)
            // Insert spaces in-between all tokens, except in the following
            // cases:
            // - No space after "(" and "["
            // - No space before ")" and "]"
            // - No space before ":"
            // - No space before or after ".." (e.g: (0..10))
            // - No space before or after "." (e.g: foo.bar)
            // - No space in-between identifiers and "(" or "[" (e.g: array[0],
            //   func("foo")).
            // - No space before or after "-" in pattern modifiers and hex jumps
            //   (e.g: xor(0-255), [0-10]).
            .add_rule(
                |ctx| {
                    let prev_token = ctx.token(-1);
                    let next_token = ctx.token(1);

                    // Insert space if previous token is anything except ( or [,
                    // and next token is anything except ) or ].
                    let add_space = prev_token.is(*TEXT ^ *LGROUPING)
                        && next_token.is(*TEXT ^ *RGROUPING);

                    let drop_space =
                        // Don't insert space if next token is ":"
                        next_token.eq(&COLON)
                        // Don't insert space after "-"
                        || prev_token.eq(&HYPHEN)
                        // Don't insert spaces around "."
                        || prev_token.eq(&DOT)
                        || next_token.eq(&DOT)
                        // don't insert space in-between some identifier and "("
                        // or "[".
                        || prev_token.is(*IDENTIFIER)
                            && next_token.is(*LGROUPING)
                        // don't insert spaces before "(" in pattern modifiers.
                        || ctx.in_rule(SyntaxKind::PATTERN_MOD, false)
                            && next_token.is(*LGROUPING)
                        // don't insert spaces before or after "-" in pattern
                        // modifiers and hex jumps.
                        || (ctx.in_rule(SyntaxKind::PATTERN_MOD, false) ||
                            ctx.in_rule(SyntaxKind::HEX_JUMP, false))
                            && (next_token.eq(&HYPHEN) || prev_token.eq(&HYPHEN));

                    add_space && !drop_space
                },
                processor::actions::space,
            )
            // Insert two spaces before trailing comments in a line.
            .add_rule(
                |ctx| {
                    ctx.token(-1).is(*TEXT) &&
                    ctx.token(1).is(*COMMENT)
                },
                |ctx| {
                    ctx.push_output_token(Some(Whitespace));
                    ctx.push_output_token(Some(Whitespace));
                }
            )
    }
}
