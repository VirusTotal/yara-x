/*! This module implements [Language Server Protocol (LSP)][1] for YARA-X.

By implementing [`async_lsp::LanguageServer`] trait for [`ServerState`], it
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
    SemanticTokenModifier, SemanticTokenType, SemanticTokensFullOptions,
    SemanticTokensLegend, SemanticTokensOptions, SemanticTokensResult,
    SemanticTokensServerCapabilities, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions,
    TextDocumentSyncSaveOptions, TextEdit, Url, WorkspaceEdit,
};

use async_lsp::router::Router;
use async_lsp::{ClientSocket, LanguageClient, LanguageServer, ResponseError};

use futures::future::BoxFuture;

use yara_x_parser::cst::{CSTStream, CST};
use yara_x_parser::Parser;

use crate::features::{
    completion, diagnostics, document_highlight, document_symbol, goto, hover,
    references, rename, selection_range, semtokens,
};

/// Stores the state of the Language Server.
pub struct ServerState {
    /// Client socket for communication with the Development Tool.
    ///
    /// Mainly used to send notifications sush as diagnostics updates,
    /// logging and showing messages, etc.
    client: ClientSocket,

    /// Hashmap containing opened documents.
    documents: HashMap<Url, String>,

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

/// Implements document synchonization and various LSP features.
///
/// The features itself are implemented in [`crate::features`] module,
/// this trait is responsible for routing the request to appropriate feature.
impl LanguageServer for ServerState {
    type Error = ResponseError;
    type NotifyResult = ControlFlow<async_lsp::Result<()>>;

    fn initialize(
        &mut self,
        params: InitializeParams,
    ) -> BoxFuture<'static, Result<InitializeResult, Self::Error>> {
        //Check if client supports pull model diagnostics
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
                                    token_types: vec![
                                        SemanticTokenType::KEYWORD,
                                        SemanticTokenType::STRING,
                                        SemanticTokenType::CLASS,
                                        SemanticTokenType::VARIABLE,
                                        SemanticTokenType::NUMBER,
                                        SemanticTokenType::OPERATOR,
                                        SemanticTokenType::FUNCTION,
                                        SemanticTokenType::REGEXP,
                                        SemanticTokenType::COMMENT,
                                        SemanticTokenType::PARAMETER, // Should be SemanticTokenType::MODIFIER for pattern modifiers
                                        SemanticTokenType::MACRO,
                                    ],
                                    token_modifiers: vec![SemanticTokenModifier::DEFINITION],
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

    fn hover(
        &mut self,
        params: HoverParams,
    ) -> BoxFuture<'static, Result<Option<Hover>, Self::Error>> {
        let uri = params.text_document_position_params.text_document.uri;
        let text = self.documents.get(&uri).cloned();

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(hover::hover_cst(
                        cst,
                        &text,
                        params.text_document_position_params.position,
                    )
                    .map(|contents| Hover { contents, range: None }))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn definition(
        &mut self,
        params: GotoDefinitionParams,
    ) -> BoxFuture<'static, Result<Option<GotoDefinitionResponse>, Self::Error>>
    {
        let uri = params.text_document_position_params.text_document.uri;
        let text = self.documents.get(&uri).cloned();

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(goto::go_to_definition(
                        cst,
                        &text,
                        params.text_document_position_params.position,
                    )
                    .map(|range| {
                        GotoDefinitionResponse::Scalar(Location { uri, range })
                    }))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn references(
        &mut self,
        params: ReferenceParams,
    ) -> BoxFuture<'static, Result<Option<Vec<Location>>, Self::Error>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let text = self.documents.get(&uri).cloned();

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(references::find_references(cst, &text, position, uri))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn completion(
        &mut self,
        params: CompletionParams,
    ) -> BoxFuture<'static, Result<Option<CompletionResponse>, Self::Error>>
    {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let text = self.documents.get(&uri).cloned();

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(completion::completion(cst, &text, position))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn document_highlight(
        &mut self,
        params: DocumentHighlightParams,
    ) -> BoxFuture<'static, Result<Option<Vec<DocumentHighlight>>, Self::Error>>
    {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let text = self.documents.get(&uri).cloned();

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(document_highlight::document_highlight(
                        cst, &text, position,
                    ))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn document_symbol(
        &mut self,
        params: DocumentSymbolParams,
    ) -> BoxFuture<'static, Result<Option<DocumentSymbolResponse>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let text = self.documents.get(&uri).cloned();

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(document_symbol::document_symbol(cst, &text))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn semantic_tokens_full(
        &mut self,
        params: <SemanticTokensFullRequest as Request>::Params,
    ) -> BoxFuture<'static, Result<Option<SemanticTokensResult>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let text = self.documents.get(&uri).cloned();

        Box::pin(async move {
            if let Some(text) = text {
                let cststream = CSTStream::from(Parser::new(text.as_bytes()));
                Ok(Some(SemanticTokensResult::Tokens(
                    semtokens::semantic_tokens(cststream, &text),
                )))
            } else {
                Ok(None)
            }
        })
    }

    fn rename(
        &mut self,
        params: RenameParams,
    ) -> BoxFuture<'static, Result<Option<WorkspaceEdit>, Self::Error>> {
        let uri = params.text_document_position.text_document.uri;
        let text = self.documents.get(&uri).cloned();
        let new_name = params.new_name;
        let pos = params.text_document_position.position;

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(rename::rename(cst, &text, new_name, pos).map(
                        |text_edits| {
                            let mut changes: HashMap<Url, Vec<TextEdit>> =
                                HashMap::new();
                            changes.insert(uri, text_edits);
                            WorkspaceEdit::new(changes)
                        },
                    ))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    fn selection_range(
        &mut self,
        params: SelectionRangeParams,
    ) -> BoxFuture<'static, Result<Option<Vec<SelectionRange>>, Self::Error>>
    {
        let text = self.documents.get(&params.text_document.uri).cloned();
        let positions = params.positions;

        Box::pin(async move {
            if let Some(text) = text {
                if let Ok(cst) = CST::try_from(Parser::new(text.as_bytes())) {
                    Ok(selection_range::selection_range(cst, positions, &text))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
    }

    /// This function is called only for pull model diagnostics.
    fn document_diagnostic(
        &mut self,
        params: DocumentDiagnosticParams,
    ) -> BoxFuture<'static, Result<DocumentDiagnosticReportResult, Self::Error>>
    {
        let diagnostics = self
            .documents
            .get(&params.text_document.uri)
            .map(|text| diagnostics::get_diagnostic_vec(&text))
            .unwrap_or_default();

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

        self.documents.insert(uri.clone(), text.clone());

        self.publish_diagnostics(&uri);

        ControlFlow::Continue(())
    }

    fn did_save(
        &mut self,
        params: DidSaveTextDocumentParams,
    ) -> Self::NotifyResult {
        if let Some(text) = params.text {
            let uri = params.text_document.uri;
            self.documents.insert(uri.clone(), text.clone());
            self.publish_diagnostics(&uri);
        }

        ControlFlow::Continue(())
    }

    fn did_change(
        &mut self,
        params: DidChangeTextDocumentParams,
    ) -> Self::NotifyResult {
        let uri = params.text_document.uri;

        for change in params.content_changes.iter() {
            self.documents.insert(uri.clone(), change.text.clone());
        }

        self.publish_diagnostics(&uri);

        ControlFlow::Continue(())
    }

    fn did_close(
        &mut self,
        params: DidCloseTextDocumentParams,
    ) -> Self::NotifyResult {
        let uri = params.text_document.uri;

        self.documents.remove(&uri);

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

impl ServerState {
    pub fn new_router(client: ClientSocket) -> Router<Self> {
        Router::from_language_server(Self {
            client,
            documents: HashMap::new(),
            should_send_diagnostics: true,
        })
    }

    /// Sends diagnostics for specific document if publish model is used.
    fn publish_diagnostics(&mut self, uri: &Url) {
        if self.should_send_diagnostics {
            if let Some(text) = self.documents.get(uri) {
                let _ = self.client.publish_diagnostics(
                    PublishDiagnosticsParams {
                        uri: uri.clone(),
                        diagnostics: diagnostics::get_diagnostic_vec(text),
                        version: None,
                    },
                );
            }
        }
    }
}
