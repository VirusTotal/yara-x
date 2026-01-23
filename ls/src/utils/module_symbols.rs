/*! This module contains statically generated tables of all module symbols.

It provides functions to get specific information about module symbols as various LSP objects.
*/
#![allow(non_snake_case, non_upper_case_globals)]
use async_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, Documentation, InsertTextFormat,
    MarkupContent, MarkupKind, ParameterInformation, ParameterLabel,
    SignatureHelp, SignatureInformation, TextEdit,
};
use std::collections::HashMap;
use std::sync::OnceLock;

struct ItemModule {
    pub doc: Option<&'static str>,
    pub structure: Option<ItemStructure>,
    pub insert_text: Option<&'static str>,
    pub kind: CompletionItemKind,
    pub sign_info: Option<SignatureInformation>,
}

enum ItemStructure {
    Single(&'static HashMap<&'static str, Vec<ItemModule>>),
    Indexed(&'static HashMap<&'static str, Vec<ItemModule>>),
}

#[derive(Debug)]
pub enum Segment {
    Field(String),
    Index,
}

include!(concat!(env!("OUT_DIR"), "/module_tables.rs"));

/// Returns suggestions for all fields in the structure or module specified by `path`.
pub fn get_module_proposals(
    path: Vec<Segment>,
) -> Option<Vec<CompletionItem>> {
    let mut result: Vec<CompletionItem> = Vec::new();

    // Path starting from the name of the module
    let mut reversed_path = path.iter().rev().peekable();
    let mut current_table = __get_modules();

    while let Some(next) = reversed_path.next() {
        if let Segment::Field(name) = next {
            //Check if this field exists in the current table
            if let Some(module) = current_table.get(name.as_str()) {
                // Find next structure in the path
                if let Some(structure) = &module[0].structure {
                    match structure {
                        ItemStructure::Single(table) => {
                            if let Some(&Segment::Index) = reversed_path.peek()
                            {
                                return None;
                            }
                            current_table = table;
                        }
                        ItemStructure::Indexed(table) => {
                            if let Some(&Segment::Index) = reversed_path.peek()
                            {
                                current_table = table;
                            } else {
                                return None;
                            }
                        }
                    }
                } else {
                    return None; // No further structure
                }
            } else {
                return None; // Field not found
            }
        }
    }

    for (key, values) in current_table {
        let label = key.to_string();
        let additional_text_edits: Option<Vec<TextEdit>> = None;

        values.iter().for_each(|value| {
            result.push(CompletionItem {
                label: label.clone(),
                kind: Some(value.kind),
                documentation: value.doc.map(|val| {
                    Documentation::MarkupContent(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: val.to_string(),
                    })
                }),
                insert_text: value
                    .insert_text
                    .map(|insert_text| insert_text.to_string()),
                insert_text_format: value
                    .insert_text
                    .map(|_| InsertTextFormat::SNIPPET),
                additional_text_edits: additional_text_edits.clone(),
                ..Default::default()
            })
        });
    }

    Some(result)
}

/// Returns signature help for the functions specified by `idents` path.
pub fn get_signature_help(
    mut idents: Vec<String>,
    argument_order: i32,
) -> Option<SignatureHelp> {
    let mut current_table = __get_modules();
    let mut current_item: &Vec<ItemModule> = &vec![];

    // Find the functions for this path
    while let Some(ident) = idents.pop() {
        current_item = current_table.get(ident.as_str())?;
        if let Some(structure) = &current_item[0].structure {
            current_table = match structure {
                ItemStructure::Single(table) => table,
                ItemStructure::Indexed(table) => table,
            };
        } else if idents.is_empty() {
            break;
        } else {
            return None;
        }
    }

    // Find only functions
    let mut informations: Vec<SignatureInformation> = Vec::new();
    for item in current_item {
        if item.kind == CompletionItemKind::FUNCTION {
            if let Some(sign_info) = &item.sign_info {
                informations.push(sign_info.clone());
            }
        }
    }

    Some(SignatureHelp {
        signatures: informations,
        active_signature: Some(0),
        active_parameter: Some((argument_order - 1) as u32),
    })
}
