use std::sync::Arc;

use async_lsp::lsp_types::{
    InlayHint, InlayHintKind, InlayHintLabel, Range, Url,
};
use yara_x_parser::ast::{
    AST, Expr, Iterable, WithSpan,
    dfs::{DFSEvent, DFSIter},
};

use crate::{
    documents::storage::DocumentStorage,
    utils::modules::{from_expr, ty_to_string},
};

use yara_x::mods::reflect::Type;

pub fn inlay_hint(
    documents: Arc<DocumentStorage>,
    uri: Url,
    target_range: Range,
) -> Option<Vec<InlayHint>> {
    let document = documents.get(&uri)?;
    let line_index = &document.line_index;
    let ast = AST::new(document.text.as_bytes(), document.cst.iter());
    let target_span = line_index.range_to_span(target_range);

    let mut result = Vec::new();

    for condition in ast.rules().map(|rule| &rule.condition) {
        // Do not traverse conditions that are outside the target span.
        if target_span.end() < condition.span().start()
            || condition.span().end() < target_span.start()
        {
            continue;
        }

        let dfs = DFSIter::new(condition);
        for event in dfs {
            match event {
                DFSEvent::Enter(Expr::With(with_expr)) => {
                    for decl in &with_expr.declarations {
                        // Do not traverse expressions that are outside the target span.
                        if target_span.end() < decl.span().start()
                            || decl.span().end() < target_span.start()
                        {
                            break;
                        }
                        if let Some(mut ty) = from_expr(&decl.expression) {
                            // Extract return type from function.
                            ty = if let Type::Func(func) = &ty
                                && let Some(new_ty) = func
                                    .signatures
                                    .first()
                                    .map(|sign| &sign.ret)
                            {
                                new_ty.clone()
                            } else {
                                ty
                            };

                            result.push(InlayHint {
                                position: line_index.offset_to_position(
                                    decl.identifier.span().end(),
                                ),
                                label: InlayHintLabel::String(format!(
                                    ": {}",
                                    ty_to_string(&ty)
                                )),
                                kind: Some(InlayHintKind::TYPE),
                                text_edits: None,
                                tooltip: None,
                                padding_left: None,
                                padding_right: None,
                                data: None,
                            });
                        }
                    }
                }
                DFSEvent::Enter(Expr::ForIn(for_expr)) => {
                    // Do not traverse expressions that are outside of the target span.
                    if target_span.end() < for_expr.iterable.span().start()
                        || for_expr.iterable.span().end() < target_span.start()
                    {
                        break;
                    }

                    if let Iterable::Expr(expr) = &for_expr.iterable
                        && let Some(mut ty) = from_expr(expr)
                    {
                        // Extract return type from function.
                        ty = if let Type::Func(func) = &ty
                            && let Some(new_ty) =
                                func.signatures.first().map(|sign| &sign.ret)
                        {
                            new_ty.clone()
                        } else {
                            ty
                        };

                        if let Some(first) = for_expr.variables.first() {
                            if let Some(second) = for_expr.variables.get(1) {
                                // Extract map types.
                                if let Type::Map(ty1, ty2) = ty {
                                    result.push(InlayHint {
                                        position: line_index
                                            .offset_to_position(
                                                first.span().end(),
                                            ),
                                        label: InlayHintLabel::String(
                                            format!(
                                                ": {}",
                                                ty_to_string(&ty1)
                                            ),
                                        ),
                                        kind: Some(InlayHintKind::TYPE),
                                        text_edits: None,
                                        tooltip: None,
                                        padding_left: None,
                                        padding_right: None,
                                        data: None,
                                    });

                                    result.push(InlayHint {
                                        position: line_index
                                            .offset_to_position(
                                                second.span().end(),
                                            ),
                                        label: InlayHintLabel::String(
                                            format!(
                                                ": {}",
                                                ty_to_string(&ty2)
                                            ),
                                        ),
                                        kind: Some(InlayHintKind::TYPE),
                                        text_edits: None,
                                        tooltip: None,
                                        padding_left: None,
                                        padding_right: None,
                                        data: None,
                                    });
                                }
                            } else {
                                // Extract array type.
                                let ty = if let Type::Array(arr) = &ty {
                                    *arr.clone()
                                } else {
                                    continue;
                                };

                                result.push(InlayHint {
                                    position: line_index.offset_to_position(
                                        first.span().end(),
                                    ),
                                    label: InlayHintLabel::String(format!(
                                        ": {}",
                                        ty_to_string(&ty)
                                    )),
                                    kind: Some(InlayHintKind::TYPE),
                                    text_edits: None,
                                    tooltip: None,
                                    padding_left: None,
                                    padding_right: None,
                                    data: None,
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Some(result)
}
