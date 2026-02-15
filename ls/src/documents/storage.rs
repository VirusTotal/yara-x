use std::{collections::HashSet, fs};

use async_lsp::lsp_types::Url;
use dashmap::{mapref::one::Ref, DashMap};
use yara_x_parser::cst::{Immutable, Node, SyntaxKind, CST};

use crate::{
    documents::document::Document, utils::cst_traversal::rule_from_ident,
};

#[derive(Default)]
pub struct DocumentStorage {
    opened: DashMap<Url, Document>,
    workspace: Option<Url>,
}

impl DocumentStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, uri: &Url) -> Option<Ref<'_, Url, Document>> {
        self.opened.get(uri)
    }

    pub fn insert(&self, uri: Url, text: String) {
        self.opened.insert(uri.clone(), Document::new(uri, text));
    }

    pub fn update(&self, uri: Url, text: String) {
        if let Some(mut document) = self.opened.get_mut(&uri) {
            document.update(text);
        }
    }

    pub fn remove(&self, uri: &Url) -> Option<(Url, Document)> {
        self.opened.remove(uri)
    }

    pub fn set_workspace(&mut self, uri: Url) {
        self.workspace = Some(uri);
    }

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    fn get_document_cst_root(&self, uri: &Url) -> Option<Node<Immutable>> {
        if let Some(doc) = self.get(uri) {
            Some(doc.cst.root())
        } else {
            uri.to_file_path().ok().and_then(|path| {
                fs::read_to_string(path)
                    .ok()
                    .map(|content| CST::from(content.as_str()).root())
            })
        }
    }

    #[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
    fn get_document_cst_root(&self, uri: &Url) -> Option<Node<Immutable>> {
        self.get(uri).map(|doc| doc.cst.root())
    }

    pub fn find_rule_definition(
        &self,
        uri: &Url,
        ident: &str,
    ) -> Option<(Node<Immutable>, Url)> {
        let mut includes = vec![uri.clone()];
        let mut accessed: HashSet<Url> = HashSet::new();

        while let Some(curr) = includes.pop() {
            let root: Node<Immutable>;

            if let Some(_root) = self.get_document_cst_root(&curr) {
                root = _root;
                if let Some(rule) = rule_from_ident(&root, ident) {
                    return Some((rule, curr));
                }
            } else {
                continue;
            }

            // Push include URLs from this file
            for include in root
                .children()
                .filter(|child| child.kind() == SyntaxKind::INCLUDE_STMT)
            {
                if let Some(include_token) = include.last_token() {
                    if include_token.kind() != SyntaxKind::STRING_LIT {
                        continue;
                    }

                    let include_text = include_token.text();
                    let include_len = include_text.len();

                    if let Ok(new_uri) =
                        curr.join(&include_text[1..include_len - 1])
                    {
                        if !accessed.contains(&new_uri) {
                            includes.push(new_uri);
                        }
                    }
                }
            }

            accessed.insert(curr);
        }

        None
    }
}
