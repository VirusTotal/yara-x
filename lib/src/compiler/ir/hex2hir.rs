/*! Functions for converting a hex pattern AST into a HIR. */

use regex_syntax::hir;
use yara_x_parser::ast;

use crate::compiler::ByteMaskCombinator;

pub(in crate::compiler) fn hex_pattern_hir_from_ast(
    pattern: &ast::HexPattern,
) -> hir::Hir {
    hex_tokens_hir_from_ast(&pattern.tokens)
}

fn hex_tokens_hir_from_ast(tokens: &ast::HexTokens) -> hir::Hir {
    let mut hir_tokens = Vec::with_capacity(tokens.tokens.len());

    for token in &tokens.tokens {
        match token {
            ast::HexToken::Byte(byte) => {
                hir_tokens.push(hex_byte_hir_from_ast(byte));
            }
            ast::HexToken::NotByte(byte) => {
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
                    alternatives.push(hex_tokens_hir_from_ast(alt));
                }

                hir_tokens.push(hir::Hir::alternation(alternatives))
            }
            ast::HexToken::Jump(jump) => {
                hir_tokens.push(hir::Hir::repetition(hir::Repetition {
                    min: jump.start.map(|start| start as u32).unwrap_or(0),
                    max: jump.end.map(|end| end as u32),
                    greedy: false,
                    sub: Box::new(hir::Hir::dot(hir::Dot::AnyByte)),
                }))
            }
        }
    }

    hir::Hir::concat(hir_tokens)
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
    use super::hex_byte_to_class;
    use crate::re::hir::class_to_masked_byte;
    use pretty_assertions::assert_eq;
    use regex_syntax::hir::{
        Class, ClassBytes, ClassBytesRange, Dot, Hir, HirKind, Repetition,
    };
    use yara_x_parser::ast::{
        HexAlternative, HexByte, HexJump, HexToken, HexTokens,
    };

    #[test]
    fn hex_byte_to_hir() {
        let hir =
            super::hex_byte_hir_from_ast(&HexByte { value: 0x00, mask: 0x00 });
        assert_eq!(hir.to_string(), r"(?-u:[\x00-\xFF])");

        let hir =
            super::hex_byte_hir_from_ast(&HexByte { value: 0x10, mask: 0xf0 });
        assert_eq!(hir.to_string(), r"(?-u:[\x10-\x1F])");

        let hir =
            super::hex_byte_hir_from_ast(&HexByte { value: 0x02, mask: 0x0f });
        assert_eq!(
            hir.to_string(),
            r#"(?-u:[\x02\x12"2BRbr\x82\x92\xA2\xB2\xC2\xD2\xE2\xF2])"#
        );
    }

    #[test]
    fn hex_tokens_to_hir() {
        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: b'a', mask: 0xff }),
                HexToken::Byte(HexByte { value: b'b', mask: 0xff }),
                HexToken::Byte(HexByte { value: b'c', mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::literal("abc".as_bytes())
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::literal([0x01, 0x02, 0x03])
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x00, mask: 0x00 }),
                HexToken::Byte(HexByte { value: 0x05, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x06, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::dot(Dot::AnyByte),
                Hir::literal([0x05, 0x06]),
            ])
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::NotByte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::class(Class::Bytes(ClassBytes::new(vec![
                    ClassBytesRange::new(0, 1),
                    ClassBytesRange::new(3, 255)
                ]))),
                Hir::literal([0x03]),
            ])
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::NotByte(HexByte { value: 0x40, mask: 0xfe }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::class(Class::Bytes(ClassBytes::new(vec![
                    ClassBytesRange::new(0, 0x3f),
                    ClassBytesRange::new(0x42, 0xff),
                ]))),
                Hir::literal([0x03]),
            ])
        );

        let tokens = HexTokens {
            tokens: vec![HexToken::Alternative(Box::new(HexAlternative {
                alternatives: vec![
                    HexTokens {
                        tokens: vec![HexToken::Byte(HexByte {
                            value: 0x01,
                            mask: 0xff,
                        })],
                    },
                    HexTokens {
                        tokens: vec![HexToken::Byte(HexByte {
                            value: 0x02,
                            mask: 0xff,
                        })],
                    },
                ],
            }))],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::alternation(
                vec![Hir::literal([0x01]), Hir::literal([0x02]),]
            )
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
                HexToken::Jump(HexJump { start: None, end: None }),
                HexToken::Byte(HexByte { value: 0x05, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x06, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::repetition(Repetition {
                    min: 0,
                    max: None,
                    greedy: false,
                    sub: Box::new(Hir::dot(Dot::AnyByte)),
                }),
                Hir::literal([0x05, 0x06]),
            ])
        );
    }

    #[test]
    fn class_to_hex() {
        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&HexByte {
                value: 0x30,
                mask: 0xF0
            })),
            Some(HexByte { value: 0x30, mask: 0xF0 })
        );

        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&HexByte {
                value: 0x05,
                mask: 0x0F
            })),
            Some(HexByte { value: 0x05, mask: 0x0F })
        );

        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&HexByte {
                value: 0x08,
                mask: 0xAA
            })),
            Some(HexByte { value: 0x08, mask: 0xAA })
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
                Some(HexByte { value: 0x00, mask: 0x00 })
            );
        } else {
            unreachable!()
        }
    }
}
