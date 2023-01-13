//! This crate implements a code formatter for YARA rules, in the spirit of
//! other tools like `rustfmt` and `gofmt`.
//!
//! # Usage
//!
//! ```no_run
//!# use std::fs::File;
//! use yara_x_fmt::Formatter;
//!
//! let input = File::open("original.yar").unwrap();
//! let output = File::create("formatted.yar").unwrap();
//!
//! Formatter::new().format(input, output).unwrap();
//! ```
use std::io;

use thiserror::Error;
use yara_x_parser::GrammarRule;
use yara_x_parser::Parser;

use tokens::Token::*;
use tokens::TokenStream;

use crate::align::Align;
use crate::tokens::categories::*;
use crate::tokens::*;

mod align;
mod bubble;
mod comments;
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

    /// Error while parsing the input.
    #[error("Parse error")]
    ParseError(#[from] yara_x_parser::Error),
}

/// Formats YARA source code automatically.
pub struct Formatter {
    indent: String,
}

impl Default for Formatter {
    fn default() -> Self {
        Self::new()
    }
}

// Formatter public API.
impl Formatter {
    /// Creates a new formatter.
    pub fn new() -> Self {
        Formatter { indent: "  ".to_string() }
    }

    pub fn indentation(&mut self, indentation: &str) -> &mut Self {
        self.indent = indentation.to_string();
        self
    }

    /// Reads YARA source code from `input` and write it into `output` after
    /// formatting.
    ///
    /// This function will fail if it can't read from the input, write to the
    /// output, or when the input doesn't contain syntactically valid YARA
    /// rules.
    pub fn format<R, W>(&self, mut input: R, output: W) -> Result<(), Error>
    where
        R: io::Read,
        W: io::Write,
    {
        let mut buf = String::new();

        // Read the source code from input and store it in buf.
        input.read_to_string(&mut buf).map_err(Error::ReadError)?;

        let parser = Parser::new();

        // Build a CST that maintains comments and whitespaces.
        let cst =
            parser.build_cst(buf.as_str())?.comments(true).whitespaces(true);

        // Generate a stream of tokens from the CST.
        let tokens = tokens::Tokens::new(cst);

        Formatter::formatter(tokens)
            .write_to(output, self.indent.as_str())
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

        // Displace tail comments to the left with respect to tokens that
        // indicate the end of a grammar rule. This effectively moves such
        // comments to the innermost grammar rule.
        let tokens = bubble::Bubble::new(
            tokens,
            |token| matches!(token, Token::TailComment(_)),
            |token| matches!(token, Token::End(_)),
        );

        // Displace newlines to the right with respect to tokens that indicate
        // the end of a grammar rule. This effectively moves them to the
        // outermost grammar rule. See the documentation for the `bubble`
        // module for more details.
        let tokens = bubble::Bubble::new(
            tokens,
            |token| matches!(token, Token::End(_)),
            |token| token.is(*NEWLINE),
        );

        let tokens = processor::Processor::new(tokens).add_rule(
            |ctx| {
                dbg!(ctx.token(1));
                false
            },
            processor::actions::drop,
        );

        // Remove newlines in multiple cases.
        let tokens = processor::Processor::new(tokens)
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
                    (ctx.in_rule(GrammarRule::rule_mods)
                        || ctx.in_rule(GrammarRule::rule_tags))
                        && ctx.token(-1).is_not(*COMMENT)
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after rule modifiers.
            .add_rule(
                |ctx| {
                    ctx.token(-1).eq(&End(GrammarRule::rule_mods))
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after rule tags
            .add_rule(
                |ctx| {
                    ctx.token(-1).eq(&End(GrammarRule::rule_tags))
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after "meta:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::meta_defs)
                        && ctx.token(-1).eq(&COLON)
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines after "strings:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::pattern_defs)
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

                    next_token.eq(&Begin(GrammarRule::import_stmt))
                        && prev_token.neq(&Begin(GrammarRule::source_file))
                        && prev_token.is_not(*NEWLINE)
                },
                processor::actions::newline,
            )
            .add_rule(
                |ctx| {
                    ctx.token(1).is(*COMMENT)
                        && ctx.token(2).eq(&Begin(GrammarRule::rule_decl))
                        && ctx.token(-1).is_not(*NEWLINE)
                },
                |ctx| {
                    ctx.push_output_token(Some(Newline));
                    let comment = ctx.pop_input_token();
                    ctx.push_output_token(comment);
                    ctx.push_output_token(Some(Newline));
                },
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

                    next_token.eq(&Begin(GrammarRule::rule_decl))
                        && prev_token.neq(&Begin(GrammarRule::source_file))
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
                    ctx.token(1).eq(&Begin(GrammarRule::rule_decl))
                        && ctx.token(-1).is(*NEWLINE)
                        && ctx.token(-2).is_not(*NEWLINE | *COMMENT)
                },
                processor::actions::newline,
            )
            //
            // Similar to the rule above, but handles the case where the rule
            // is preceded by a comment.
            //
            //  rule foo {
            //    ...
            //  }
            //  // Comment
            //  rule bar {
            //    ...
            //  }
            //
            //  Inserts newline before comment
            //
            .add_rule(
                |ctx| {
                    ctx.token(1).is(*COMMENT)
                        && ctx.token(2).is(*NEWLINE)
                        && ctx.token(3).eq(&Begin(GrammarRule::rule_decl))
                        && ctx.token(-1).is(*NEWLINE)
                        && ctx.token(-2).is_not(*NEWLINE)
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
                        Keyword("meta")
                            | Keyword("strings")
                            | Keyword("condition")
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
                            Keyword("meta")
                                | Keyword("strings")
                                | Keyword("condition")
                        )
                },
                processor::actions::newline,
            )
            // Add newline in front of pattern identifiers in the "strings"
            // section.
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::pattern_def)
                        && ctx.token(1).is(*IDENTIFIER)
                        && ctx.token(-1).is_not(*NEWLINE)
                },
                processor::actions::newline,
            )
            // Add newline before the closing brace at the end of rule.
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(1).eq(&RBRACE)
                        && ctx.token(-1).is_not(*NEWLINE)
                },
                processor::actions::newline,
            );

        let tokens = Self::indent_body(tokens);
        let tokens = Self::indent_sections(tokens);

        // indent_body and indent_sections will insert Indentation tokens, but
        // won't take into account that those tokens must appear before the
        // newline they are expected to affect. This fixes the issue by moving
        // indentation tokens in front of newline tokens if they appear in
        // reverse order.
        let tokens = bubble::Bubble::new(
            tokens,
            |token| matches!(token, Token::Indentation(_)),
            |token| token.is(*NEWLINE),
        );

        let tokens = processor::Processor::new(tokens)
            .set_passthrough(*CONTROL)
            .add_rule(
                |ctx| {
                    matches!(
                        ctx.token(-1),
                        Token::TailComment(_) | Token::BlockComment(_)
                    ) && ctx.token(1).is_not(*NEWLINE)
                },
                processor::actions::newline,
            );

        let tokens = Self::add_spacing(tokens);
        let tokens = Self::align(tokens);

        tokens
    }

    /// Indents the sections (meta, strings, condition) of a rule one level up.
    /// For example, for this input..
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
    ///
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
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(-1).eq(&COLON)
                },
                processor::actions::insert(Indentation(1)),
            )
            // Decrease indentation after the condition.
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(-1).eq(&End(GrammarRule::boolean_expr))
                },
                processor::actions::insert(Indentation(-1)),
            )
            // Increase indentation after "meta:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::meta_defs)
                        && ctx.token(-1).eq(&COLON)
                },
                processor::actions::insert(Indentation(1)),
            )
            // Decrease indentation after meta definitions
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::meta_defs)
                        && ctx.token(1).eq(&End(GrammarRule::meta_defs))
                        && ctx.token(-1).neq(&Indentation(-1))
                },
                processor::actions::insert(Indentation(-1)),
            )
            // Increase indentation after "strings:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::pattern_defs)
                        && ctx.token(-1).eq(&COLON)
                },
                processor::actions::insert(Indentation(1)),
            )
            // Decrease indentation after pattern definitions.
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::pattern_defs)
                        && ctx.token(1).eq(&End(GrammarRule::pattern_defs))
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
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(-1).eq(&LBRACE)
                },
                processor::actions::insert(Indentation(1)),
            )
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(1).eq(&RBRACE)
                        && ctx.token(-1).neq(&Indentation(-1))
                },
                processor::actions::insert(Indentation(-1)),
            )
    }

    /// Aligns the equals signs in pattern definitions. For example, for this
    /// input..
    ///
    /// rule foo {
    ///   strings:
    ///     $short = "foo"
    ///     $very_long = "bar"
    ///     $even_longer = "baz"
    ///   condition:
    ///     true
    /// }
    ///
    /// ... the result is ...
    ///
    /// rule foo {
    ///   strings:
    ///     $short       = "foo"
    ///     $very_long   = "bar"
    ///     $even_longer = "baz"
    ///   condition:
    ///     true
    /// }
    ///
    /// The input must must contain at least one newline character after each
    /// pattern definition.
    fn align<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        // First insert the alignment markers at the appropriate places...
        let input_with_markers = processor::Processor::new(input)
            .add_rule(
                |ctx| ctx.token(-1).eq(&Begin(GrammarRule::pattern_defs)),
                processor::actions::insert(AlignmentBlockBegin),
            )
            .add_rule(
                |ctx| {
                    ctx.token(1).eq(&End(GrammarRule::pattern_defs))
                        && ctx.token(-1).neq(&AlignmentBlockEnd)
                },
                processor::actions::insert(AlignmentBlockEnd),
            )
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::pattern_def)
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
            // - No space in-between identifiers and "(" or "[" (e.g: array[0], func("foo")).
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
                        // Don't insert spaces around ".."
                        || prev_token.eq(&DOT_DOT)
                        || next_token.eq(&DOT_DOT)
                        // Don't insert spaces around "."
                        || prev_token.eq(&DOT)
                        || next_token.eq(&DOT)
                        // don't insert space in-between some identifier and "("
                        // or "[".
                        || prev_token.is(*IDENTIFIER)
                            && next_token.is(*LGROUPING)
                        // don't insert spaces before "(" in pattern modifiers.
                        || ctx.in_rule(GrammarRule::pattern_mods) && next_token.is(*LGROUPING)
                        // don't insert spaces before or after "-" in pattern 
                        // modifiers and hex jumps.
                        || (ctx.in_rule(GrammarRule::pattern_mods) ||
                            ctx.in_rule(GrammarRule::hex_jump))
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
