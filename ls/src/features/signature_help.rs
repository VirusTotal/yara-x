use std::sync::Arc;

use crate::{
    documents::storage::DocumentStorage,
    utils::{
        cst_traversal::{prev_non_trivia_token, token_at_position},
        modules::{get_struct, ty_to_string},
    },
};
use async_lsp::lsp_types::{
    ParameterInformation, ParameterLabel, Position, SignatureHelp,
    SignatureInformation, Url,
};
use yara_x::mods::reflect::Type;
use yara_x_parser::cst::SyntaxKind;

pub fn signature_help(
    documents: Arc<DocumentStorage>,
    pos: Position,
    uri: Url,
) -> Option<SignatureHelp> {
    let cst = &documents.get(&uri)?.cst;
    let mut curr = token_at_position(cst, pos)?.prev_token();

    let mut paren_counter = 1;
    let mut active_parameter = 0;

    while let Some(token) = curr {
        match token.kind() {
            SyntaxKind::L_PAREN => {
                paren_counter -= 1;
                // Get the last token of function call.
                if paren_counter == 0 {
                    curr = prev_non_trivia_token(&token);
                    break;
                }
            }
            SyntaxKind::R_PAREN => {
                paren_counter += 1;
            }
            SyntaxKind::COMMA => {
                // Count the position of the active parameter
                // at the cursor within the scope of the parentheses.
                if paren_counter == 1 {
                    active_parameter += 1;
                }
            }
            // Avoid traversing entire file.
            SyntaxKind::CONDITION_KW => return None,
            _ => {}
        }
        curr = token.prev_token();
    }

    let last_ident = curr?;

    let func = match get_struct(&last_ident) {
        Some(Type::Func(func)) => Some(func),
        _ => None,
    }?;

    let mut signatures = Vec::new();
    let singature_start = format!("{}(", last_ident.text());

    for signature in func.signatures {
        // Ignore singatures that have less parameters.
        if (active_parameter + 1) as usize > signature.args.len() {
            continue;
        }

        let mut curr_signature = singature_start.clone();
        let mut param_iterator = signature.args.iter();
        let mut param_info = Vec::new();

        // Traverse all parameters and insert `, ` to the label,
        // if the parameters is not last.
        if let Some(mut curr_type) = param_iterator.next() {
            loop {
                let ty_str = ty_to_string(curr_type);
                param_info.push(ParameterInformation {
                    label: ParameterLabel::LabelOffsets([
                        curr_signature.len() as u32,
                        (curr_signature.len() + ty_str.len()) as u32,
                    ]),
                    documentation: None,
                });
                curr_signature.push_str(&ty_str);
                if let Some(next_type) = param_iterator.next() {
                    curr_signature.push_str(", ");
                    curr_type = next_type;
                } else {
                    break;
                }
            }
        }

        curr_signature.push_str(") -> ");
        curr_signature.push_str(&ty_to_string(&signature.ret));

        signatures.push(SignatureInformation {
            label: curr_signature,
            documentation: None,
            parameters: Some(param_info),
            active_parameter: None,
        });
    }

    Some(SignatureHelp {
        signatures,
        active_parameter: Some(active_parameter),
        active_signature: None,
    })
}
