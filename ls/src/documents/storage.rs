use std::collections::{HashMap, HashSet};

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
use std::fs;

use async_lsp::lsp_types::{FileChangeType, FileEvent, Url};
use dashmap::{mapref::one::Ref, DashMap};
use yara_x_parser::cst::{Immutable, Node, SyntaxKind, Token, CST};

use crate::{
    documents::document::Document,
    utils::cst_traversal::{get_includes, rule_from_ident, rule_usages},
};

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
use walkdir::WalkDir;

pub struct OccurrencesResult {
    pub definition: (Url, Node<Immutable>),
    pub usages: HashMap<Url, Vec<Token<Immutable>>>,
}

#[derive(Default)]
pub struct DocumentStorage {
    opened: DashMap<Url, Document>,
    cached: DashMap<Url, CST>,
    workspace: Option<Url>,
}

impl DocumentStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a reference to the document with a specific URI.
    pub fn get(&self, uri: &Url) -> Option<Ref<'_, Url, Document>> {
        self.opened.get(uri)
    }

    /// Inserts a new document with the specified content.
    pub fn insert(&self, uri: Url, text: String) {
        self.opened.insert(uri.clone(), Document::new(uri, text));
    }

    /// Updates document content and its internal structures.
    pub fn update(&self, uri: Url, text: String) {
        if let Some(mut document) = self.opened.get_mut(&uri) {
            document.update(text);
        }
    }

    /// Removes the document and returns (key,value) before removing.
    pub fn remove(&self, uri: &Url) -> Option<(Url, Document)> {
        self.opened.remove(uri)
    }

    /// Sets workspace folder to the specified URI.
    pub fn set_workspace(&mut self, uri: Url) {
        self.workspace = Some(uri);
    }

    /// Gets root [`yara_x_parser::cst::Node`] either from opened document,
    /// or reads the file to parse the tree.
    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    fn get_document_cst_root(&self, uri: &Url) -> Option<Node<Immutable>> {
        if let Some(doc) = self.get(uri) {
            Some(doc.cst.root())
        } else if let Some(cst) = self.cached.get(uri) {
            Some(cst.root())
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

    /// Recursively traverse all YARA files in the workspace using
    /// [`walkdir::WalkDir`].
    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    fn walk_workspace(&self) -> Option<impl Iterator<Item = Url>> {
        self.workspace.as_ref().and_then(|uri| uri.to_file_path().ok()).map(
            |workspace_path| {
                WalkDir::new(workspace_path)
                    .into_iter()
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| {
                        entry.path().extension().is_some_and(|ext| {
                            ext.to_str().is_some_and(|ext| {
                                matches!(ext, "yar" | "yara")
                            })
                        })
                    })
                    .filter_map(|dir_entry| {
                        Url::from_file_path(dir_entry.into_path()).ok()
                    })
            },
        )
    }

    #[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
    fn walk_workspace(&self) -> Option<impl Iterator<Item = Url>> {
        None::<std::iter::Empty<Url>>
    }

    /// Finds the definition of the rule with the given `ident`.
    ///
    /// It looks into the document identified by the given `uri` and all its
    /// includes.
    pub fn find_rule_definition(
        &self,
        uri: &Url,
        ident: &Token<Immutable>,
    ) -> Option<(Node<Immutable>, Url)> {
        assert_eq!(ident.kind(), SyntaxKind::IDENT);

        let mut includes = vec![uri.clone()];
        let mut accessed: HashSet<Url> = HashSet::new();

        while let Some(curr) = includes.pop() {
            let root = match self.get_document_cst_root(&curr) {
                Some(node) => node,
                None => continue,
            };

            if let Some(rule) = rule_from_ident(&root, ident) {
                return Some((rule, curr));
            }

            // Push include URIs from this file
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

                    // Ignore empty includes
                    if include_len < 3 {
                        continue;
                    }

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

    /// Finds all occurrences of the rule with the specified `ident` only
    /// within the current workspace or opened documents. The occurrences
    /// include the rule definition and any use of the rule in the condition
    /// of other rules.
    pub fn find_rule_occurrences(
        &self,
        uri: &Url,
        ident: &Token<Immutable>,
    ) -> Option<OccurrencesResult> {
        let (rule, rule_uri) = self.find_rule_definition(uri, ident)?;

        let mut usages = HashMap::new();

        // If the workspace folder is set then traverse it.
        // Otherwise, only opened documents are processed.
        let file_entries = if let Some(workspace) = self.walk_workspace() {
            workspace.collect::<Vec<Url>>()
        } else {
            self.opened
                .iter()
                .map(|entry| entry.key().clone())
                .collect::<Vec<Url>>()
        };

        // This hashmap stores information about all includes.
        let mut include_cache: HashMap<Url, Vec<Url>> = HashMap::new();

        // Walk over entire workspace to resolve all includes.
        // At the same time process files which have as include
        // file in which target rule is defined, to minimize
        // amount of double file read.
        for entry in file_entries {
            if let Some(root) = self.get_document_cst_root(&entry) {
                // Indicates if current entry (file) includes the file in which
                // target rule was defined.
                let mut includes_origin = false;

                // If it is not the same file as where the rule defined,
                // then deal with includes.
                if entry != rule_uri {
                    for include in root.children().filter(|child| {
                        child.kind() == SyntaxKind::INCLUDE_STMT
                    }) {
                        if let Some(include_token) = include.last_token() {
                            if include_token.kind() != SyntaxKind::STRING_LIT {
                                continue;
                            }

                            let include_text = include_token.text();
                            let include_len = include_text.len();

                            // Ignore empty includes
                            if include_len < 3 {
                                continue;
                            }

                            if let Ok(new_uri) =
                                entry.join(&include_text[1..include_len - 1])
                            {
                                if rule_uri == new_uri {
                                    includes_origin = true;
                                }
                                include_cache
                                    .entry(new_uri)
                                    .or_default()
                                    .push(entry.clone());
                            }
                        }
                    }
                }
                // Otherwise,just try to find usages within this file.
                else {
                    includes_origin = true;
                }

                if !includes_origin {
                    continue;
                }

                if let Some(occurrences) = rule_usages(&root, ident) {
                    usages.insert(entry, occurrences);
                }
            }
        }

        // Where the rule potentially can be used and should be checked
        let mut to_access =
            include_cache.remove(&rule_uri).unwrap_or_default();

        // File, that were already checked
        let mut accessed: HashSet<Url> = HashSet::new();

        // Now it should traverse nested includes
        while let Some(included_in) = to_access.pop() {
            if let Some(next_includes) = include_cache.remove(&included_in) {
                for current in &next_includes {
                    if !accessed.contains(current) {
                        if let Some(occurrences) =
                            self.get_document_cst_root(current).and_then(
                                |nested_root| rule_usages(&nested_root, ident),
                            )
                        {
                            usages.insert(current.clone(), occurrences);
                        }
                        accessed.insert(current.clone());
                        to_access.push(current.clone());
                    }
                }
            }
        }

        Some(OccurrencesResult { usages, definition: (rule_uri, rule) })
    }

    /// This function collects all rules that were included from other
    /// files as [`yara_x_parser::cst::Token`] and also stores its
    /// relative path to the `base` URI of the origin document.
    pub fn included_rules(
        &self,
        base_root: Node<Immutable>,
        base: &Url,
    ) -> Vec<(String, Token<Immutable>)> {
        let mut includes = get_includes(&base_root, base);
        let mut accessed: HashSet<Url> = HashSet::new();
        let mut rules: Vec<(String, Token<Immutable>)> = vec![];

        while let Some(included) = includes.pop() {
            if !accessed.contains(&included) {
                if let Some(root) = self.get_document_cst_root(&included) {
                    includes.extend(get_includes(&root, &included));

                    let relative_path =
                        base.make_relative(&included).unwrap_or_default();

                    root.children()
                        .filter(|child| child.kind() == SyntaxKind::RULE_DECL)
                        .for_each(|rule_decl| {
                            if let Some(ident) = rule_decl
                                .children_with_tokens()
                                .find(|node_or_token| {
                                    node_or_token.kind() == SyntaxKind::IDENT
                                })
                                .and_then(|node_or_token| {
                                    node_or_token.into_token()
                                })
                            {
                                rules.push((relative_path.clone(), ident));
                            }
                        });
                }

                accessed.insert(included);
            }
        }

        rules
    }

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    pub fn cache_workspace(&self) {
        if let Some(workspace_files) = self
            .walk_workspace()
            .map(|workspace| workspace.collect::<Vec<Url>>())
        {
            for entry in workspace_files {
                if self.opened.contains_key(&entry) {
                    continue;
                }

                if let Some(cst) = entry
                    .to_file_path()
                    .ok()
                    .and_then(|path| fs::read_to_string(path).ok())
                    .map(|content| CST::from(content.as_str()))
                {
                    self.cached.insert(entry, cst);
                }
            }
        }
    }

    #[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
    pub fn cache_workspace(&self) {}

    pub fn clear_cache(&self) {
        self.cached.clear();
    }

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    pub fn react_watched_files_changes(&self, changes: Vec<FileEvent>) {
        for change in changes {
            // Opened files are synchronized in `textDocument/did*` methods.
            if self.opened.contains_key(&change.uri) {
                continue;
            }

            match change.typ {
                FileChangeType::CHANGED | FileChangeType::CREATED => {
                    if let Some(cst) =
                        change.uri.to_file_path().ok().and_then(|path| {
                            fs::read_to_string(path)
                                .ok()
                                .map(|content| CST::from(content.as_str()))
                        })
                    {
                        self.cached.insert(change.uri, cst);
                    }
                }
                FileChangeType::DELETED => {
                    self.cached.remove(&change.uri);
                }
                _ => {}
            }
        }
    }

    #[cfg(any(target_arch = "wasm32", target_arch = "wasm64"))]
    pub fn react_watched_files_changes(&self, changes: Vec<FileEvent>) {}
}
