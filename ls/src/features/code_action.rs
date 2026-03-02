use std::collections::HashMap;

use async_lsp::lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, Diagnostic, Range,
    TextEdit, Url, WorkspaceEdit,
};

use crate::features::diagnostics::DiagnosticData;

/// Returns a list of code actions (quick fixes) for the given source code.
///
/// This function relies on the diagnostics provided by the client, which
/// should contain the necessary data to apply the fixes.
pub fn code_actions(
    uri: &Url,
    diagnostics: Vec<Diagnostic>,
) -> Vec<CodeActionOrCommand> {
    let mut actions = Vec::new();

    for diagnostic in diagnostics {
        if let Some(data) = &diagnostic.data {
            if let Ok(data) =
                serde_json::from_value::<DiagnosticData>(data.clone())
            {
                for patch in data.patches {
                    let action = create_code_action(
                        format!("Fix: {}", diagnostic.message),
                        uri.clone(),
                        patch.range,
                        patch.replacement,
                    );
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
        }
    }

    actions
}

/// Creates a CodeAction with a workspace edit that applies a text replacement.
fn create_code_action(
    title: String,
    uri: Url,
    range: Range,
    new_text: String,
) -> CodeAction {
    let text_edit = TextEdit { range, new_text };

    let mut changes = HashMap::new();
    changes.insert(uri, vec![text_edit]);

    CodeAction {
        title,
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: None,
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            document_changes: None,
            change_annotations: None,
        }),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    }
}
