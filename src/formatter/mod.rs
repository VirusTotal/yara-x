//! Formats YARA source code automatically.
//!
//! # Usage
//!
//! ```no_run
//!# use std::fs::File;
//! use yara_x::formatter::Formatter;
//!
//! let input = File::open("original.yar").unwrap();
//! let output = File::create("formatted.yar").unwrap();
//!
//! Formatter::new().format(input, output);
//! ```
use std::io;

use thiserror::Error;

use tokens::Token::*;
use tokens::TokenStream;

use crate::formatter::aligner::Aligner;
use crate::formatter::tokens::categories::*;
use crate::parser;
use crate::parser::GrammarRule;
use crate::parser::Parser;

mod aligner;
mod comments;
mod processor;
mod tokens;
mod trailing_spaces;

#[cfg(test)]
mod tests;

/// Represents the errors returned by [`Formatter::format`].
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// Represents a failure while reading from input.
    #[error("Read error")]
    ReadError(io::Error),

    /// Represents a failure while writing to output.
    #[error("Write error")]
    WriteError(io::Error),

    /// Represents a failure while parsing the input.
    #[error("Parse error")]
    ParseError(#[from] parser::Error),
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

    pub fn format<R, W>(&self, mut input: R, output: W) -> Result<(), Error>
    where
        R: std::io::Read,
        W: std::io::Write,
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
        // Remove all whitespaces from the original source.
        let tokens = processor::Processor::new(input).add_rule(
            |ctx| ctx.token(1).is(*WHITESPACE),
            processor::actions::drop,
        );

        let tokens = processor::Processor::new(tokens)
            // Remove excess of newlines, only two consecutive newlines are
            // allowed.
            .add_rule(
                |ctx| {
                    ctx.token(-2).is(*NEWLINE)
                        && ctx.token(-1).is(*NEWLINE)
                        && ctx.token(1).is(*NEWLINE)
                },
                processor::actions::drop,
            )
            // Remove newlines in between rule modifiers "private" and "global"
            .add_rule(
                |ctx| {
                    (ctx.in_rule(GrammarRule::rule_decl)
                        || ctx.in_rule(GrammarRule::rule_mods)
                        || ctx.in_rule(GrammarRule::rule_tags))
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
                        && !ctx.token(-2).is(*NEWLINE | *COMMENT)
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
                    ) && !ctx.token(-1).is(*NEWLINE)
                },
                processor::actions::newline,
            )
            // Add newline after "meta:", "strings:" and "condition:".
            .add_rule(
                |ctx| {
                    !ctx.in_rule(GrammarRule::rule_tags)
                        && ctx.token(-1).eq(&Punctuation(":"))
                        && !ctx.token(1).is(*NEWLINE)
                },
                processor::actions::newline,
            )
            // Add newline in front of pattern identifiers in the "strings"
            // section.
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::pattern_def)
                        && ctx.token(1).is(*IDENTIFIER)
                        && !ctx.token(-1).is(*NEWLINE)
                },
                processor::actions::newline,
            )
            // Add newline before the closing brace at the end of rule.
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(1).eq(&Punctuation("}"))
                        && !ctx.token(-1).is(*NEWLINE)
                },
                processor::actions::newline,
            );

        let tokens = Self::indent_body(tokens);
        let tokens = Self::indent_sections(tokens);

        // indent_body and indent_sections will insert Indentation tokens, but
        // won't take into account that those tokens must appear before the
        // newline they are expected to affect. This processor fixes that by
        // moving the Indentation tokens in front of Newline tokens if they
        // appear in reverse order.
        let tokens = processor::Processor::new(tokens)
            // Ignore all control tokens except indentation.
            .set_passthrough(*CONTROL ^ *INDENTATION)
            // Swap newlines followed by indentations. Notice that there are
            // two rules, one that swaps tokens at positions 2 and 3, and
            // another one that swaps tokens at positions 1 and 2. This is
            // because we want a sequence [Newline, Newline, Indentation]
            // ending up as [Indentation, Newline, Newline]. Swapping positions
            // 1 and 2 is not enough because the first two tokens [Newline,
            // Newline] don't match the rule, causing the first Newline to
            // be copied to the output. The following Newline and Indentation,
            // are swapped later, resulting in output [Newline, Indentation,
            // Newline].
            // By using two rules we make sure that tokens at positions 2 and 3
            // are swapped first, and then tokens at position 1 and 2 will be
            // swapped in the next iteration if necessary. But this strategy
            // works as long as we don't have more than two consecutive
            // newlines, a sequence [Newline, Newline, Newline, Indentation]
            // ends up being [Newline, Indentation, Newline, Newline] not
            // [Indentation, Newline, Newline, Newline]. That's ok because
            // a previous step reduces sequences of more than two consecutive
            // newlines to two of them.
            .add_rule(
                |ctx| {
                    ctx.token(2).is(*NEWLINE) && ctx.token(3).is(*INDENTATION)
                },
                processor::actions::swap(2, 3),
            )
            .add_rule(
                |ctx| {
                    ctx.token(1).is(*NEWLINE) && ctx.token(2).is(*INDENTATION)
                },
                processor::actions::swap(1, 2),
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
            .set_passthrough(*COMMENT)
            // Increase indentation after "condition:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(-1).eq(&Punctuation(":"))
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
            // Increase indentation after "strings:"
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::pattern_defs)
                        && ctx.token(-1).eq(&Punctuation(":"))
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
            .set_passthrough(*COMMENT)
            // Increase indentation after the opening brace in a rule
            // declaration.
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(-1).eq(&Punctuation("{"))
                },
                processor::actions::insert(Indentation(1)),
            )
            .add_rule(
                |ctx| {
                    ctx.in_rule(GrammarRule::rule_decl)
                        && ctx.token(1).eq(&Punctuation("}"))
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
                        && ctx.token(1).eq(&Punctuation("="))
                        && ctx.token(-1).neq(&AlignmentMarker)
                },
                processor::actions::insert(AlignmentMarker),
            );

        // ... then pass the token stream with the markers to Aligner, which
        // returns a token stream that replaces the markers with the
        // appropriate number of spaces.
        Aligner::new(input_with_markers)
    }

    fn add_spacing<'a, I>(input: I) -> impl TokenStream<'a> + 'a
    where
        I: TokenStream<'a> + 'a,
    {
        processor::Processor::new(input)
            .set_passthrough(*CONTROL)
            // Insert spaces in-between all tokens, but keep "meta:", "strings:"
            // "conditions:" without spaces before the colon (:).
            .add_rule(
                |ctx| {
                    let prev_token = ctx.token(-1);
                    let next_token = ctx.token(1);

                    next_token.is(*TEXT)
                        && prev_token.is(*TEXT)
                        && !matches!(
                            prev_token,
                            Keyword("meta")
                                | Keyword("strings")
                                | Keyword("condition")
                        )
                },
                processor::actions::space,
            )
    }
}
