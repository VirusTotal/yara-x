/*! Functions for converting a hex pattern AST into a HIR. */

use regex_syntax::hir;
use yara_x_parser::ast;
use yara_x_parser::ast::WithSpan;

use crate::compiler::context::CompileContext;
use crate::compiler::errors::{CompileError, InvalidPattern};
use crate::compiler::{warnings, ByteMaskCombinator};

pub(in crate::compiler) fn hex_pattern_hir_from_ast(
    ctx: &mut CompileContext,
    pattern: &ast::HexPattern,
) -> Result<hir::Hir, CompileError> {
    hex_tokens_hir_from_ast(ctx, &pattern.identifier, &pattern.tokens)
}

fn hex_tokens_hir_from_ast(
    ctx: &mut CompileContext,
    pattern_ident: &ast::Ident,
    tokens: &ast::HexTokens,
) -> Result<hir::Hir, CompileError> {
    let mut hir_tokens = Vec::with_capacity(tokens.tokens.len());
    let mut ast_tokens = tokens.tokens.iter().peekable();

    while let Some(token) = ast_tokens.next() {
        match token {
            ast::HexToken::Byte(byte) => {
                hir_tokens.push(hex_byte_hir_from_ast(byte));
            }
            ast::HexToken::NotByte(byte) => {
                // ~?? is not allowed.
                if byte.mask == 0 {
                    return Err(InvalidPattern::build(
                        ctx.report_builder,
                        pattern_ident.name.to_string(),
                        "negation of `??` is not allowed".to_string(),
                        token.span().into(),
                        None,
                    ));
                }

                let class = match hex_byte_hir_from_ast(byte).into_kind() {
                    hir::HirKind::Class(mut class) => {
                        class.negate();
                        class
                    }
                    hir::HirKind::Literal(literal) => {
                        let mut class = hir::ClassBytes::empty();
                        for b in literal.0.iter() {
                            class.push(hir::ClassBytesRange::new(*b, *b));
                        }
                        class.negate();
                        hir::Class::Bytes(class)
                    }
                    _ => unreachable!(),
                };

                hir_tokens.push(hir::Hir::class(class));
            }
            ast::HexToken::Alternative(alt) => {
                let mut alternatives =
                    Vec::with_capacity(alt.alternatives.len());

                for alt in &alt.as_ref().alternatives {
                    alternatives.push(hex_tokens_hir_from_ast(
                        ctx,
                        pattern_ident,
                        alt,
                    )?);
                }

                hir_tokens.push(hir::Hir::alternation(alternatives))
            }
            ast::HexToken::Jump(jump) => {
                let mut span = jump.span();
                let mut jump = jump.clone();
                let mut coalesced = false;

                // Coalesce consecutive jumps into a single one. For example:
                //
                //  `[1-2][3-4]` becomes `[4-6]`
                //  `[0-2][5-]` becomes `[5-]`
                //  `[4][0-7]`  becomes `[4-11]`
                //
                while let Some(ast::HexToken::Jump(next)) = ast_tokens.peek() {
                    match (jump.start, next.start) {
                        (Some(s1), Some(s2)) => jump.start = Some(s1 + s2),
                        (Some(s1), None) => jump.start = Some(s1),
                        (None, Some(s2)) => jump.start = Some(s2),
                        (None, None) => jump.start = None,
                    }
                    match (jump.end, next.end) {
                        (Some(e1), Some(e2)) => jump.end = Some(e1 + e2),
                        (_, _) => jump.end = None,
                    }
                    span = span.combine(&next.span());
                    ast_tokens.next();
                    coalesced = true;
                }

                if coalesced {
                    ctx.warnings.add(|| {
                        warnings::ConsecutiveJumps::build(
                            ctx.report_builder,
                            pattern_ident.name.to_string(),
                            format!("{jump}"),
                            (&span).into(),
                        )
                    });
                }

                match (jump.start, jump.end) {
                    (Some(0), Some(0)) => {
                        return Err(InvalidPattern::build(
                            ctx.report_builder,
                            pattern_ident.name.to_string(),
                            "zero-length jumps are useless, remove it"
                                .to_string(),
                            span.into(),
                            None,
                        ));
                    }
                    (Some(start), Some(end)) if start > end => {
                        return Err(InvalidPattern::build(
                            ctx.report_builder,
                            pattern_ident.name.to_string(),
                            format!(
                                "lower bound ({start}) is greater than upper bound ({end})"),
                            span.into(),
                            if coalesced {
                                Some("consecutive jumps were coalesced into a single one".to_string())
                            } else {
                                None
                            }
                        ));
                    }
                    _ => {}
                }

                hir_tokens.push(hir::Hir::repetition(hir::Repetition {
                    min: jump.start.map(|start| start as u32).unwrap_or(0),
                    max: jump.end.map(|end| end as u32),
                    greedy: false,
                    sub: Box::new(hir::Hir::dot(hir::Dot::AnyByte)),
                }))
            }
        }
    }

    Ok(hir::Hir::concat(hir_tokens))
}

fn hex_byte_hir_from_ast(byte: &ast::HexByte) -> hir::Hir {
    match byte.mask {
        0xff => hir::Hir::literal([byte.value]),
        0x00 => hir::Hir::dot(hir::Dot::AnyByte),
        _ => hir::Hir::class(hir::Class::Bytes(hex_byte_to_class(byte))),
    }
}

fn hex_byte_to_class(b: &ast::HexByte) -> hir::ClassBytes {
    // A zero bit in the mask indicates that the corresponding bit in the value
    // will be ignored, but those ignored bits should be set to 0.
    assert_eq!(b.value & !b.mask, 0);

    let mut class = hir::ClassBytes::empty();
    for b in ByteMaskCombinator::new(b.value, b.mask) {
        class.push(hir::ClassBytesRange::new(b, b));
    }

    class
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use regex_syntax::hir::{
        Class, ClassBytes, ClassBytesRange, Dot, Hir, HirKind, Repetition,
    };
    use yara_x_parser::ast;

    use yara_x_parser::ast::{
        HexAlternative, HexJump, HexPattern, HexToken, HexTokens, Ident,
    };

    use super::hex_byte_to_class;
    use crate::compiler::context::{CompileContext, VarStack};
    use crate::compiler::report::ReportBuilder;
    use crate::compiler::Warnings;
    use crate::re::hir;
    use crate::re::hir::class_to_masked_byte;
    use crate::symbols::StackedSymbolTable;

    #[test]
    fn hex_byte_to_hir() {
        let hir = super::hex_byte_hir_from_ast(&ast::HexByte::new(0x00, 0x00));
        assert_eq!(hir.to_string(), r"(?-u:[\x00-\xFF])");

        let hir = super::hex_byte_hir_from_ast(&ast::HexByte::new(0x10, 0xf0));
        assert_eq!(hir.to_string(), r"(?-u:[\x10-\x1F])");

        let hir = super::hex_byte_hir_from_ast(&ast::HexByte::new(0x02, 0x0f));
        assert_eq!(
            hir.to_string(),
            r#"(?-u:[\x02\x12"2BRbr\x82\x92\xA2\xB2\xC2\xD2\xE2\xF2])"#
        );
    }

    #[test]
    fn hex_tokens_to_hir() {
        let mut report_builder = ReportBuilder::default();
        let mut symbol_table = StackedSymbolTable::new();
        let mut warnings = Warnings::default();
        let mut rule_patterns = vec![];

        let mut ctx = CompileContext {
            relaxed_re_syntax: false,
            error_on_slow_loop: false,
            current_symbol_table: None,
            symbol_table: &mut symbol_table,
            report_builder: &mut report_builder,
            current_rule_patterns: &mut rule_patterns,
            warnings: &mut warnings,
            vars: VarStack::new(),
            for_of_depth: 0,
        };

        let mut pattern = HexPattern {
            identifier: Ident::new("test_ident"),
            tokens: HexTokens {
                tokens: vec![
                    HexToken::Byte(ast::HexByte::new(b'a', 0xff)),
                    HexToken::Byte(ast::HexByte::new(b'b', 0xff)),
                    HexToken::Byte(ast::HexByte::new(b'c', 0xff)),
                ],
            },
            ..Default::default()
        };

        assert_eq!(
            super::hex_pattern_hir_from_ast(&mut ctx, &pattern),
            Ok(Hir::literal("abc".as_bytes()))
        );

        pattern.tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(ast::HexByte::new(0x01, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x02, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x03, 0xff)),
            ],
        };

        assert_eq!(
            super::hex_pattern_hir_from_ast(&mut ctx, &pattern),
            Ok(Hir::literal([0x01, 0x02, 0x03]))
        );

        pattern.tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(ast::HexByte::new(0x01, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x02, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x03, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x00, 0x00)),
                HexToken::Byte(ast::HexByte::new(0x05, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x06, 0xff)),
            ],
        };

        assert_eq!(
            super::hex_pattern_hir_from_ast(&mut ctx, &pattern),
            Ok(Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::dot(Dot::AnyByte),
                Hir::literal([0x05, 0x06]),
            ]))
        );

        pattern.tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(ast::HexByte::new(0x01, 0xff)),
                HexToken::NotByte(ast::HexByte::new(0x02, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x03, 0xff)),
            ],
        };

        assert_eq!(
            super::hex_pattern_hir_from_ast(&mut ctx, &pattern),
            Ok(Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::class(Class::Bytes(ClassBytes::new(vec![
                    ClassBytesRange::new(0, 1),
                    ClassBytesRange::new(3, 255)
                ]))),
                Hir::literal([0x03]),
            ]))
        );

        pattern.tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(ast::HexByte::new(0x01, 0xff)),
                HexToken::NotByte(ast::HexByte::new(0x40, 0xfe)),
                HexToken::Byte(ast::HexByte::new(0x03, 0xff)),
            ],
        };

        assert_eq!(
            super::hex_pattern_hir_from_ast(&mut ctx, &pattern),
            Ok(Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::class(Class::Bytes(ClassBytes::new(vec![
                    ClassBytesRange::new(0, 0x3f),
                    ClassBytesRange::new(0x42, 0xff),
                ]))),
                Hir::literal([0x03]),
            ]))
        );

        pattern.tokens = HexTokens {
            tokens: vec![HexToken::Alternative(Box::new(
                HexAlternative::new(vec![
                    HexTokens {
                        tokens: vec![HexToken::Byte(ast::HexByte::new(
                            0x01, 0xff,
                        ))],
                    },
                    HexTokens {
                        tokens: vec![HexToken::Byte(ast::HexByte::new(
                            0x02, 0xff,
                        ))],
                    },
                ]),
            ))],
        };
        assert_eq!(
            super::hex_pattern_hir_from_ast(&mut ctx, &pattern),
            Ok(Hir::alternation(vec![
                Hir::literal([0x01]),
                Hir::literal([0x02]),
            ]))
        );

        pattern.tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(ast::HexByte::new(0x01, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x02, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x03, 0xff)),
                HexToken::Jump(HexJump::new(None, None)),
                HexToken::Byte(ast::HexByte::new(0x05, 0xff)),
                HexToken::Byte(ast::HexByte::new(0x06, 0xff)),
            ],
        };

        assert_eq!(
            super::hex_pattern_hir_from_ast(&mut ctx, &pattern),
            Ok(Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::repetition(Repetition {
                    min: 0,
                    max: None,
                    greedy: false,
                    sub: Box::new(Hir::dot(Dot::AnyByte)),
                }),
                Hir::literal([0x05, 0x06]),
            ]))
        );
    }

    #[test]
    fn class_to_hex() {
        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&ast::HexByte::new(
                0x30, 0xff
            ))),
            Some(hir::HexByte { value: 0x30, mask: 0xff })
        );

        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&ast::HexByte::new(
                0x05, 0x0f
            ))),
            Some(hir::HexByte { value: 0x05, mask: 0x0f })
        );

        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&ast::HexByte::new(
                0x03, 0xff
            ))),
            Some(hir::HexByte { value: 0x03, mask: 0xff })
        );

        assert_eq!(
            class_to_masked_byte(&ClassBytes::new(vec![
                ClassBytesRange::new(3, 4),
                ClassBytesRange::new(8, 8),
            ])),
            None,
        );

        assert_eq!(
            class_to_masked_byte(&ClassBytes::new(vec![
                ClassBytesRange::new(0, 0),
                ClassBytesRange::new(2, 2),
                ClassBytesRange::new(4, 4),
            ])),
            None,
        );

        assert_eq!(
            class_to_masked_byte(&ClassBytes::new(vec![
                ClassBytesRange::new(b':', b';'),
                ClassBytesRange::new(b'|', b'|'),
                ClassBytesRange::new(b',', b','),
            ])),
            None,
        );

        if let HirKind::Class(Class::Bytes(class)) =
            Hir::dot(Dot::AnyByte).kind()
        {
            assert_eq!(
                class_to_masked_byte(class),
                Some(hir::HexByte { value: 0x00, mask: 0x00 })
            );
        } else {
            unreachable!()
        }
    }
}
