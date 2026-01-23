use async_lsp::lsp_types::{Position, SignatureHelp, SignatureHelpContext};
use yara_x_parser::cst::SyntaxKind;

use crate::{
    document::Document,
    utils::{
        cst_traversal::token_at_position, module_symbols::get_signature_help,
    },
};

pub fn signature_help(
    document: &Document,
    pos: Position,
    context: Option<SignatureHelpContext>,
) -> Option<SignatureHelp> {
    let cst = &document.cst;

    let signature_help_cursor = token_at_position(cst, pos)?;

    let mut prev_token = signature_help_cursor.prev_token();
    let mut level = 1;
    let mut argument_order = 1;

    // Find the opening parenthesis of the function call
    while let Some(token) = &prev_token {
        match token.kind() {
            SyntaxKind::COMMA => {
                if level == 1 {
                    argument_order += 1;
                }
            }
            SyntaxKind::L_PAREN => {
                level -= 1;
            }
            SyntaxKind::R_PAREN => {
                level += 1;
            }
            _ => {}
        }
        prev_token = token.prev_token();
        if level == 0 {
            break;
        }
    }

    //Check that this is a function call
    let func_ident = prev_token?;
    if func_ident.kind() != SyntaxKind::IDENT {
        return None;
    }

    let mut idents = vec![func_ident.text().to_string()];

    let mut prev = func_ident.prev_token();

    while let Some(token) = prev {
        match token.kind() {
            SyntaxKind::IDENT => {
                idents.push(token.text().to_string());
            }
            SyntaxKind::DOT => {}
            _ => {
                break;
            }
        }
        prev = token.prev_token();
    }

    let mut signature_help = get_signature_help(idents, argument_order)?;

    // If there is active signature info that is still valid, then change active signature accordingly
    if let Some(index) = context
        .and_then(|c| c.active_signature_help)
        .and_then(|a| a.active_signature)
    {
        if let Some(active_info) =
            signature_help.signatures.get(index as usize)
        {
            for (i, sig_info) in signature_help.signatures.iter().enumerate() {
                if sig_info.label == active_info.label {
                    signature_help.active_signature = Some(i as u32);
                    break;
                }
            }
        }
    }

    Some(signature_help)
}
