/*! This module implements [Language Server Protocol (LSP)][1] for YARA-X.

By implementing [`async_lsp::LanguageServer`] trait for [`YARALanguageServer`], it
defines how the server should process various LSP requests and notifications.

[1]: https://microsoft.github.io/language-server-protocol/
 */

use std::collections::HashMap;
use std::ops::ControlFlow;

use async_lsp::lsp_types::request::{Request, SemanticTokensFullRequest};
use async_lsp::lsp_types::{
    CompletionOptions, CompletionParams, CompletionResponse,
    DiagnosticOptions, DiagnosticServerCapabilities,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    DocumentDiagnosticParams, DocumentDiagnosticReportResult,
    DocumentHighlight, DocumentHighlightParams, DocumentSymbolParams,
    DocumentSymbolResponse, FullDocumentDiagnosticReport,
    GotoDefinitionParams, GotoDefinitionResponse, Hover, HoverParams,
    HoverProviderCapability, InitializeParams, InitializeResult, Location,
    OneOf, PublishDiagnosticsParams, ReferenceParams,
    RelatedFullDocumentDiagnosticReport, RenameParams, SaveOptions,
    SelectionRange, SelectionRangeParams, SelectionRangeProviderCapability,
    SemanticTokensFullOptions, SemanticTokensLegend, SemanticTokensOptions,
    SemanticTokensResult, SemanticTokensServerCapabilities,
    ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextDocumentSyncOptions, TextDocumentSyncSaveOptions, Url, WorkspaceEdit,
};

use async_lsp::router::Router;
use async_lsp::{ClientSocket, LanguageClient, LanguageServer, ResponseError};
use futures::future::BoxFuture;

use yara_x_parser::ast::AST;
use yara_x_parser::cst::CST;

use crate::features::completion::completion;
use crate::features::diagnostics::diagnostics;
use crate::features::document_highlight::document_highlight;
use crate::features::document_symbol::document_symbol;
use crate::features::goto::go_to_definition;
use crate::features::hover::hover;
use crate::features::references::find_references;
use crate::features::rename::rename;
use crate::features::selection_range::selection_range;
use crate::features::semantic_tokens::{
    semantic_tokens, SEMANTIC_TOKEN_MODIFIERS, SEMANTIC_TOKEN_TYPES,
};

pub struct DocumentStore {
    documents: HashMap<Url, CST>,
}

impl DocumentStore {
    fn new() -> Self {
        Self { documents: HashMap::new() }
    }

    fn get(&self, url: &Url) -> Option<&CST> {
        self.documents.get(url)
    }

    fn insert(&mut self, url: Url, document: CST) {
        self.documents.insert(url, document);
    }

    fn remove(&mut self, url: &Url) -> Option<CST> {
        self.documents.remove(url)
    }
}

/// Represents a YARA language server.
pub struct YARALanguageServer {
    /// Client socket for communication with the Development Tool.
    ///
    /// Mainly used to send notifications sush as diagnostics updates,
    /// logging and showing messages, etc.
    client: ClientSocket,

    /// Stores the currently open documents.
    documents: DocumentStore,

    /// Flag indicating what document diagnostics model to use.
    ///
    /// There are two models: publish and pull. The publish model specifies
    /// that the server will send notifications to the client about new
    /// diagnostics for certain documents. Whereas the pull model specifies
    /// that the client will request for diagnostics of specific documents.
    ///
    /// The client can specify if it supports pull model in
    /// `textDocument.diagnostic` capability property. If the client supports
    /// pull model, server will disable publishing diagnostics.
    should_send_diagnostics: bool,
}

/// Implements document synchronization and various LSP features.
///
/// The features itself are implemented in [`crate::features`] module,
/// this trait is responsible for routing the request to appropriate feature.
impl LanguageServer for YARALanguageServer {
    type Error = ResponseError;
    type NotifyResult = ControlFlow<async_lsp::Result<()>>;

    fn initialize(
        &mut self,
        params: InitializeParams,
    ) -> BoxFuture<'static, Result<InitializeResult, Self::Error>> {
        // Check if client supports pull model diagnostics
        if let Some(capabilities_td) = params.capabilities.text_document {
            if capabilities_td.diagnostic.is_some() {
                self.should_send_diagnostics = false;
            }
        }

        Box::pin(async move {
            Ok(InitializeResult {
                capabilities: ServerCapabilities {
                    semantic_tokens_provider: Some(
                        SemanticTokensServerCapabilities::SemanticTokensOptions(
                            SemanticTokensOptions {
                                full: Some(SemanticTokensFullOptions::Bool(true)),
                                legend: SemanticTokensLegend {
                                    token_types: Vec::from(SEMANTIC_TOKEN_TYPES),
                                    token_modifiers: Vec::from(SEMANTIC_TOKEN_MODIFIERS),
                                },
                                ..Default::default()
                            },
                        ),
                    ),
                    hover_provider: Some(HoverProviderCapability::Simple(true)),
                    definition_provider: Some(OneOf::Left(true)),
                    references_provider: Some(OneOf::Left(true)),
                    completion_provider: Some(CompletionOptions {
                        resolve_provider: Some(false),
                        trigger_characters: Some(vec![
                            ".".to_string(),
                            "!".to_string(),
                            "$".to_string(),
                            "@".to_string(),
                            "#".to_string(),
                        ]),
                        ..Default::default()
                    }),
                    document_highlight_provider: Some(OneOf::Left(true)),
                    document_symbol_provider: Some(OneOf::Left(true)),
                    rename_provider: Some(OneOf::Left(true)),
                    selection_range_provider: Some(SelectionRangeProviderCapability::Simple(true)),
                    text_document_sync: Some(TextDocumentSyncCapability::Options(
                        TextDocumentSyncOptions {
                            save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                                include_text: Some(true),
                            })),
                            open_close: Some(true),
                            change: Some(TextDocumentSyncKind::FULL),
                            ..Default::default()
                        },
                    )),
                    // This is for pull model diagnostics
                    diagnostic_provider: Some(DiagnosticServerCapabilities::Options(
                        DiagnosticOptions::default(),
                    )),
                    ..ServerCapabilities::default()
                },
                server_info: None,
            })
        })
    }

    /// Message received when the user hovers over some position in the
    /// source code. The response is a text in Markdown format that the
    /// editor shows as a tooltip.
    fn hover(
        &mut self,
        params: HoverParams,
    ) -> BoxFuture<'static, Result<Option<Hover>, Self::Error>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let result = hover(cst, position)
            .map(|contents| Hover { contents, range: None });

        Box::pin(async move { Ok(result) })
    }

    /// Message received when the user wants to find the place where some
    /// identifier was defined.
    ///
    /// The params include a position within the source code that should
    /// correspond to some identifier.
    fn definition(
        &mut self,
        params: GotoDefinitionParams,
    ) -> BoxFuture<'static, Result<Option<GotoDefinitionResponse>, Self::Error>>
    {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let definition = go_to_definition(cst, position).map(|range| {
            GotoDefinitionResponse::Scalar(Location { uri, range })
        });

        Box::pin(async move { Ok(definition) })
    }

    /// Message received when the user wants to find all the places where
    /// an identifier has been used.
    ///
    /// The params include a position within the source code that should
    /// correspond to some identifier.
    fn references(
        &mut self,
        params: ReferenceParams,
    ) -> BoxFuture<'static, Result<Option<Vec<Location>>, Self::Error>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let references = match find_references(cst, position) {
            Some(references) => references
                .into_iter()
                .map(|range| Location { uri: uri.clone(), range })
                .collect(),
            None => return Box::pin(async { Ok(None) }),
        };

        Box::pin(async move { Ok(Some(references)) })
    }

    fn completion(
        &mut self,
        params: CompletionParams,
    ) -> BoxFuture<'static, Result<Option<CompletionResponse>, Self::Error>>
    {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let completions =
            completion(cst, position).map(CompletionResponse::Array);

        Box::pin(async move { Ok(completions) })
    }

    fn document_highlight(
        &mut self,
        params: DocumentHighlightParams,
    ) -> BoxFuture<'static, Result<Option<Vec<DocumentHighlight>>, Self::Error>>
    {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let highlights = document_highlight(cst, position);

        Box::pin(async move { Ok(highlights) })
    }

    /// Message received when the client asks the server for symbol information.
    ///
    /// The result is a tree that shows the overall structure of the code.
    fn document_symbol(
        &mut self,
        params: DocumentSymbolParams,
    ) -> BoxFuture<'static, Result<Option<DocumentSymbolResponse>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let src = cst.root().text().to_string();
        let ast = AST::new(src.as_bytes(), cst.iter());

        let symbols = document_symbol(&src, ast);

        Box::pin(
            async move { Ok(Some(DocumentSymbolResponse::Nested(symbols))) },
        )
    }

    fn semantic_tokens_full(
        &mut self,
        params: <SemanticTokensFullRequest as Request>::Params,
    ) -> BoxFuture<'static, Result<Option<SemanticTokensResult>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let tokens = semantic_tokens(cst);

        Box::pin(async move { Ok(Some(SemanticTokensResult::Tokens(tokens))) })
    }

    /// Message sent when the user wants to rename some identifier.
    ///
    /// The params include a position within the source code that should
    /// correspond to the identifier that must be renamed.
    fn rename(
        &mut self,
        params: RenameParams,
    ) -> BoxFuture<'static, Result<Option<WorkspaceEdit>, Self::Error>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let changes = rename(cst, params.new_name, position)
            .map(|changes| HashMap::from([(uri, changes)]))
            .map(WorkspaceEdit::new)
            .unwrap_or_default();

        Box::pin(async move { Ok(Some(changes)) })
    }

    fn selection_range(
        &mut self,
        params: SelectionRangeParams,
    ) -> BoxFuture<'static, Result<Option<Vec<SelectionRange>>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let cst = match self.documents.get(&uri) {
            Some(entry) => entry,
            None => return Box::pin(async { Ok(None) }),
        };

        let ranges = selection_range(cst, params.positions);

        Box::pin(async move { Ok(ranges) })
    }

    /// This function is called only for pull model diagnostics.
    fn document_diagnostic(
        &mut self,
        params: DocumentDiagnosticParams,
    ) -> BoxFuture<'static, Result<DocumentDiagnosticReportResult, Self::Error>>
    {
        let uri = params.text_document.uri;
        let diagnostics = match self.documents.get(&uri) {
            Some(cst) => {
                let src = cst.root().text().to_string();
                let ast = AST::new(src.as_bytes(), cst.iter());
                diagnostics(ast, src.as_str())
            }
            None => vec![],
        };

        Box::pin(async move {
            Ok(DocumentDiagnosticReportResult::Report(
                async_lsp::lsp_types::DocumentDiagnosticReport::Full(
                    RelatedFullDocumentDiagnosticReport {
                        full_document_diagnostic_report:
                            FullDocumentDiagnosticReport {
                                result_id: None,
                                items: diagnostics,
                            },
                        related_documents: None,
                    },
                ),
            ))
        })
    }

    fn did_open(
        &mut self,
        params: DidOpenTextDocumentParams,
    ) -> Self::NotifyResult {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        let cst = CST::from(text.as_str());
        self.documents.insert(uri.clone(), cst);
        self.publish_diagnostics(&uri);
        ControlFlow::Continue(())
    }

    fn did_save(
        &mut self,
        params: DidSaveTextDocumentParams,
    ) -> Self::NotifyResult {
        if let Some(text) = params.text {
            let uri = params.text_document.uri;
            let cst = CST::from(text.as_str());
            self.documents.insert(uri.clone(), cst);
            self.publish_diagnostics(&uri);
        }
        ControlFlow::Continue(())
    }

    fn did_change(
        &mut self,
        params: DidChangeTextDocumentParams,
    ) -> Self::NotifyResult {
        for change in params.content_changes.into_iter() {
            self.documents.insert(
                params.text_document.uri.clone(),
                CST::from(change.text.as_str()),
            );
        }

        self.publish_diagnostics(&params.text_document.uri);
        ControlFlow::Continue(())
    }

    fn did_close(
        &mut self,
        params: DidCloseTextDocumentParams,
    ) -> Self::NotifyResult {
        self.documents.remove(&params.text_document.uri);
        ControlFlow::Continue(())
    }

    fn shutdown(
        &mut self,
        _: (),
    ) -> BoxFuture<'static, Result<(), Self::Error>> {
        Box::pin(async move { Ok(()) })
    }

    fn exit(&mut self, _: ()) -> Self::NotifyResult {
        ControlFlow::Break(Ok(()))
    }
}

impl YARALanguageServer {
    pub fn new_router(client: ClientSocket) -> Router<Self> {
        Router::from_language_server(Self {
            client,
            documents: DocumentStore::new(),
            should_send_diagnostics: true,
        })
    }

    /// Sends diagnostics for specific document if publish model is used.
    fn publish_diagnostics(&mut self, uri: &Url) {
        if self.should_send_diagnostics {
            if let Some(cst) = self.documents.get(uri) {
                let src = cst.root().text().to_string();
                let ast = AST::new(src.as_bytes(), cst.iter());
                let _ = self.client.publish_diagnostics(
                    PublishDiagnosticsParams {
                        uri: uri.clone(),
                        diagnostics: diagnostics(ast, src.as_str()),
                        version: None,
                    },
                );
            }
        }
    }
}
