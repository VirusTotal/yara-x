/*! This module implements [Language Server Protocol (LSP)][1] for YARA-X.

By implementing the [`async_lsp::LanguageServer`] trait for [`YARALanguageServer`], it
defines how the server should process various LSP requests and notifications.

[1]: https://microsoft.github.io/language-server-protocol/
 */

use std::ops::ControlFlow;
use std::sync::Arc;

use async_lsp::lsp_types::request::{
    Request, SemanticTokensFullRequest, SemanticTokensRangeRequest,
};
use async_lsp::lsp_types::{
    CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    CompletionOptions, CompletionParams, CompletionResponse,
    ConfigurationItem, ConfigurationParams, DiagnosticOptions,
    DiagnosticServerCapabilities, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, DocumentDiagnosticParams,
    DocumentDiagnosticReportResult, DocumentFormattingParams,
    DocumentHighlight, DocumentHighlightParams, DocumentSymbolParams,
    DocumentSymbolResponse, FullDocumentDiagnosticReport,
    GotoDefinitionParams, GotoDefinitionResponse, Hover, HoverParams,
    HoverProviderCapability, InitializeParams, InitializeResult, Location,
    MessageType, OneOf, PublishDiagnosticsParams, ReferenceParams,
    RelatedFullDocumentDiagnosticReport, RenameParams, SaveOptions,
    SelectionRange, SelectionRangeParams, SelectionRangeProviderCapability,
    SemanticTokensFullOptions, SemanticTokensLegend, SemanticTokensOptions,
    SemanticTokensRangeResult, SemanticTokensResult,
    SemanticTokensServerCapabilities, ServerCapabilities, ShowMessageParams,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions,
    TextDocumentSyncSaveOptions, TextEdit, Url, WorkspaceEdit,
};
use async_lsp::router::Router;
use async_lsp::{ClientSocket, LanguageClient, LanguageServer, ResponseError};
use futures::future::BoxFuture;
use serde_json::from_value;

use crate::documents::storage::DocumentStorage;
use crate::features::code_action::code_actions;
use crate::features::completion::completion;
use crate::features::diagnostics::{
    diagnostics, MetadataValidationRule, Settings,
};
use crate::features::document_highlight::document_highlight;
use crate::features::document_symbol::document_symbol;
use crate::features::formatting::formatting;
use crate::features::formatting::FormattingOptions;
use crate::features::goto::go_to_definition;
use crate::features::hover::hover;
use crate::features::references::find_references;
use crate::features::rename::rename;
use crate::features::selection_range::selection_range;
use crate::features::semantic_tokens::{
    semantic_tokens, SEMANTIC_TOKEN_MODIFIERS, SEMANTIC_TOKEN_TYPES,
};

/// Represents a YARA language server.
pub struct YARALanguageServer {
    /// Client socket for communication with the Development Tool.
    ///
    /// Mainly used to send notifications such as diagnostics updates,
    /// logging and showing messages, etc.
    client: ClientSocket,

    /// Stores the currently open documents.
    documents: Arc<DocumentStorage>,

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
/// The features themselves are implemented in [`crate::features`] module,
/// this trait is responsible for routing the request to the appropriate feature.
impl LanguageServer for YARALanguageServer {
    type Error = ResponseError;
    type NotifyResult = ControlFlow<async_lsp::Result<()>>;

    /// This method is called when the language server is initialized.
    ///
    /// It sets up the server's capabilities, indicating which features are
    /// supported. For example, it declares that the server supports hover,
    /// definition, references, code completion, etc. It also checks if the
    /// client supports pull model diagnostics and sets the
    /// `should_send_diagnostics` flag accordingly.
    fn initialize(
        &mut self,
        params: InitializeParams,
    ) -> BoxFuture<'static, Result<InitializeResult, Self::Error>> {
        // Check if client supports pull model diagnostics.
        self.should_send_diagnostics = params
            .capabilities
            .text_document
            .and_then(|c| c.diagnostic)
            .is_none();

        if let Some(folder) = params
            .workspace_folders
            .and_then(|folders| folders.first().cloned())
        {
            if let Some(documents) = Arc::get_mut(&mut self.documents) {
                documents.set_workspace(folder.uri);
            }
        }

        Box::pin(async move {
            Ok(InitializeResult {
                capabilities: ServerCapabilities {
                    semantic_tokens_provider: Some(
                        SemanticTokensServerCapabilities::SemanticTokensOptions(
                            SemanticTokensOptions {
                                full: Some(SemanticTokensFullOptions::Bool(true)),
                                range: Some(true),
                                legend: SemanticTokensLegend {
                                    token_types: Vec::from(SEMANTIC_TOKEN_TYPES),
                                    token_modifiers: Vec::from(
                                        SEMANTIC_TOKEN_MODIFIERS,
                                    ),
                                },
                                ..Default::default()
                            },
                        ),
                    ),
                    hover_provider: Some(HoverProviderCapability::Simple(true)),
                    definition_provider: Some(OneOf::Left(true)),
                    references_provider: Some(OneOf::Left(true)),
                    document_formatting_provider: Some(OneOf::Left(true)),
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
                    code_action_provider: Some(
                        CodeActionProviderCapability::Simple(true),
                    ),
                    selection_range_provider: Some(
                        SelectionRangeProviderCapability::Simple(true),
                    ),
                    text_document_sync: Some(TextDocumentSyncCapability::Options(
                        TextDocumentSyncOptions {
                            save: Some(TextDocumentSyncSaveOptions::SaveOptions(
                                SaveOptions {
                                    include_text: Some(true),
                                },
                            )),
                            open_close: Some(true),
                            change: Some(TextDocumentSyncKind::FULL),
                            ..Default::default()
                        },
                    )),
                    // This is for pull model diagnostics
                    diagnostic_provider: Some(
                        DiagnosticServerCapabilities::Options(
                            DiagnosticOptions::default(),
                        ),
                    ),
                    ..ServerCapabilities::default()
                },
                server_info: None,
            })
        })
    }

    /// This method is called when the user hovers over a symbol.
    ///
    /// It provides information about the symbol, such as its type and
    /// documentation, which is displayed as a tooltip in the editor.
    fn hover(
        &mut self,
        params: HoverParams,
    ) -> BoxFuture<'static, Result<Option<Hover>, Self::Error>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            Ok(hover(documents, uri, position)
                .map(|contents| Hover { contents, range: None }))
        })
    }

    /// This method is called when the user requests to go to the definition
    /// of a symbol.
    ///
    /// It returns the location of the symbol's definition, allowing the
    /// editor to navigate to it.
    fn definition(
        &mut self,
        params: GotoDefinitionParams,
    ) -> BoxFuture<'static, Result<Option<GotoDefinitionResponse>, Self::Error>>
    {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            Ok(go_to_definition(documents, uri, position)
                .map(GotoDefinitionResponse::Scalar))
        })
    }

    /// This method is called when the user requests to find all references
    /// to a symbol.
    ///
    /// It returns a list of all locations where the symbol is used,
    /// allowing the editor to display them.
    fn references(
        &mut self,
        params: ReferenceParams,
    ) -> BoxFuture<'static, Result<Option<Vec<Location>>, Self::Error>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            Ok(find_references(documents, uri.clone(), position))
        })
    }

    /// This method is called when the user requests code actions for a range.
    ///
    /// It provides quick fixes for errors and warnings that have patches
    /// available from the compiler.
    fn code_action(
        &mut self,
        params: CodeActionParams,
    ) -> BoxFuture<'static, Result<Option<CodeActionResponse>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let actions = code_actions(&uri, params.context.diagnostics);

        if actions.is_empty() {
            Box::pin(async { Ok(None) })
        } else {
            Box::pin(async move { Ok(Some(actions)) })
        }
    }

    /// This method is called when the user requests code completion.
    ///
    /// It provides a list of suggested completions for the current cursor
    /// position, such as keywords, identifiers, and module names. The
    /// suggestions are triggered by characters like `.`, `!`, `$`, `@`, and
    /// `#`.
    fn completion(
        &mut self,
        params: CompletionParams,
    ) -> BoxFuture<'static, Result<Option<CompletionResponse>, Self::Error>>
    {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let context = params.context;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            Ok(completion(documents, position, uri, context)
                .map(CompletionResponse::Array))
        })
    }

    /// This method is called when the user requests to highlight occurrences
    /// of a symbol in the document.
    ///
    /// It identifies all instances of the symbol at the current cursor
    /// position and returns their locations, allowing the editor to highlight
    /// them.
    fn document_highlight(
        &mut self,
        params: DocumentHighlightParams,
    ) -> BoxFuture<'static, Result<Option<Vec<DocumentHighlight>>, Self::Error>>
    {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let documents = Arc::clone(&self.documents);

        Box::pin(
            async move { Ok(document_highlight(documents, uri, position)) },
        )
    }

    /// This method is called when the client requests a list of all symbols
    /// in a document.
    ///
    /// It returns a hierarchical list of symbols, which can be used to
    /// display an outline of the document.
    fn document_symbol(
        &mut self,
        params: DocumentSymbolParams,
    ) -> BoxFuture<'static, Result<Option<DocumentSymbolResponse>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            Ok(document_symbol(documents, uri)
                .map(DocumentSymbolResponse::Nested))
        })
    }

    /// This method is called to provide semantic highlighting for the document.
    ///
    /// It analyzes the source code and returns a list of tokens with their
    /// corresponding types and modifiers, allowing the editor to apply syntax
    /// highlighting with greater accuracy.
    fn semantic_tokens_full(
        &mut self,
        params: <SemanticTokensFullRequest as Request>::Params,
    ) -> BoxFuture<'static, Result<Option<SemanticTokensResult>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            Ok(semantic_tokens(documents, uri, None)
                .map(SemanticTokensResult::Tokens))
        })
    }

    /// This method is called to provide semantic highlighting for a specific
    /// range of the document.
    ///
    /// This is more efficient than `semantic_tokens_full` for large files
    /// as it only computes tokens within the visible range.
    fn semantic_tokens_range(
        &mut self,
        params: <SemanticTokensRangeRequest as Request>::Params,
    ) -> BoxFuture<
        'static,
        Result<Option<SemanticTokensRangeResult>, Self::Error>,
    > {
        let uri = params.text_document.uri;
        let range = params.range;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            Ok(semantic_tokens(documents, uri, Some(range))
                .map(SemanticTokensRangeResult::Tokens))
        })
    }

    /// This method is called when the user wants to rename a symbol.
    ///
    /// It finds all occurrences of the symbol at the given position and
    /// returns a set of edits to rename them.
    fn rename(
        &mut self,
        params: RenameParams,
    ) -> BoxFuture<'static, Result<Option<WorkspaceEdit>, Self::Error>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let new_name = params.new_name;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move {
            let changes = rename(documents, uri.clone(), new_name, position)
                .map(WorkspaceEdit::new)
                .unwrap_or_default();

            Ok(Some(changes))
        })
    }

    /// This method is called to determine the range of the symbol at the
    /// current cursor position.
    ///
    /// It helps the editor to intelligently expand the selection, for example,
    /// from a variable to the entire statement.
    fn selection_range(
        &mut self,
        params: SelectionRangeParams,
    ) -> BoxFuture<'static, Result<Option<Vec<SelectionRange>>, Self::Error>>
    {
        let uri = params.text_document.uri;
        let positions = params.positions;
        let documents = Arc::clone(&self.documents);

        Box::pin(async move { Ok(selection_range(documents, uri, positions)) })
    }

    /// This method is called to provide diagnostic information for a document.
    ///
    /// It analyzes the source code and returns a list of diagnostics, such as
    /// errors and warnings. This method is only called if the client supports
    /// the pull model for diagnostics.
    fn document_diagnostic(
        &mut self,
        params: DocumentDiagnosticParams,
    ) -> BoxFuture<'static, Result<DocumentDiagnosticReportResult, Self::Error>>
    {
        let uri = params.text_document.uri;
        let documents = Arc::clone(&self.documents);
        let client = self.client.clone();

        Box::pin(async move {
            let settings = Self::get_settings(client, uri.clone()).await;

            Ok(DocumentDiagnosticReportResult::Report(
                async_lsp::lsp_types::DocumentDiagnosticReport::Full(
                    RelatedFullDocumentDiagnosticReport {
                        full_document_diagnostic_report:
                            FullDocumentDiagnosticReport {
                                result_id: None,
                                items: diagnostics(documents, uri, settings),
                            },
                        related_documents: None,
                    },
                ),
            ))
        })
    }

    /// It formats the source code according to the configured style and
    /// returns a set of edits to apply the changes.
    fn formatting(
        &mut self,
        params: DocumentFormattingParams,
    ) -> BoxFuture<'static, Result<Option<Vec<TextEdit>>, Self::Error>> {
        let documents = Arc::clone(&self.documents);
        let mut client = self.client.clone();

        Box::pin(async move {
            let config = client
                .configuration(ConfigurationParams {
                    items: vec![ConfigurationItem {
                        scope_uri: Some(params.text_document.uri.clone()),
                        section: Some("YARA.codeFormatting".to_string()),
                    }],
                })
                .await;

            let options = config
                .ok()
                .and_then(|mut config| config.pop())
                .and_then(|v| {
                    serde_json::from_value::<FormattingOptions>(v).ok()
                })
                .unwrap_or_default();

            Ok(formatting(documents, params, options))
        })
    }

    /// This method is called when a document is opened.
    ///
    /// It adds the document to the document store and triggers a diagnostic
    /// update.
    fn did_open(
        &mut self,
        params: DidOpenTextDocumentParams,
    ) -> Self::NotifyResult {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        self.documents.insert(uri.clone(), text);
        self.publish_diagnostics(&uri);
        ControlFlow::Continue(())
    }

    /// This method is called when a document is saved.
    ///
    /// It updates the document in the document store and triggers a
    /// diagnostic update.
    fn did_save(
        &mut self,
        params: DidSaveTextDocumentParams,
    ) -> Self::NotifyResult {
        if let Some(text) = params.text {
            let uri = params.text_document.uri;
            self.documents.insert(uri.clone(), text);
            self.publish_diagnostics(&uri);
        }
        ControlFlow::Continue(())
    }

    /// This method is called when a document is changed.
    /// This method is called when a document is changed.
    ///
    /// It updates the document in the document store and triggers a
    /// diagnostic update.
    fn did_change(
        &mut self,
        params: DidChangeTextDocumentParams,
    ) -> Self::NotifyResult {
        let uri = params.text_document.uri;
        for change in params.content_changes.into_iter() {
            self.documents.update(uri.clone(), change.text);
        }
        self.publish_diagnostics(&uri);
        ControlFlow::Continue(())
    }

    /// This method is called when a document is closed.
    ///
    /// It removes the document from the document store.
    fn did_close(
        &mut self,
        params: DidCloseTextDocumentParams,
    ) -> Self::NotifyResult {
        self.documents.remove(&params.text_document.uri);
        ControlFlow::Continue(())
    }

    /// This method is called when the server is requested to shut down.
    ///
    /// It should not exit the process, but instead, it should prepare for
    /// shutdown.
    fn shutdown(
        &mut self,
        _: (),
    ) -> BoxFuture<'static, Result<(), Self::Error>> {
        Box::pin(async move { Ok(()) })
    }

    /// This method is called to exit the server process.
    ///
    /// It should only be called after the shutdown method has been called.
    fn exit(&mut self, _: ()) -> Self::NotifyResult {
        ControlFlow::Break(Ok(()))
    }
}

impl YARALanguageServer {
    pub fn new_router(client: ClientSocket) -> Router<Self> {
        Router::from_language_server(Self {
            client,
            documents: Arc::new(DocumentStorage::new()),
            should_send_diagnostics: true,
        })
    }

    async fn get_settings(
        mut client: ClientSocket,
        scope_uri: Url,
    ) -> Settings {
        let settings = client
            .configuration(ConfigurationParams {
                items: vec![
                    ConfigurationItem {
                        scope_uri: Some(scope_uri.clone()),
                        section: Some("YARA.metadataValidation".to_string()),
                    },
                    ConfigurationItem {
                        scope_uri: Some(scope_uri),
                        section: Some("YARA.ruleNameValidation".to_string()),
                    },
                ],
            })
            .await
            .ok()
            .map(|mut v| {
                let rule_name_validation = v
                    .pop()
                    .and_then(|value| from_value::<Option<String>>(value).ok())
                    .unwrap_or_default();

                let metadata_validation = v
                    .pop()
                    .and_then(|value| {
                        from_value::<Vec<MetadataValidationRule>>(value).ok()
                    })
                    .unwrap_or_default();

                Settings { metadata_validation, rule_name_validation }
            })
            .unwrap_or_default();

        if let Some(re) = &settings.rule_name_validation {
            if regex::Regex::new(re).is_err() {
                let _ = client.show_message(ShowMessageParams {
                    typ: MessageType::ERROR,
                    message: format!(
                        "YARA: wrong rule name validation regex: {re}"
                    ),
                });
            }
        }

        settings
    }

    /// Sends diagnostics for specific document if publish model is used.
    fn publish_diagnostics(&mut self, uri: &Url) {
        if self.should_send_diagnostics {
            let documents = Arc::clone(&self.documents);
            let mut client = self.client.clone();
            let uri = uri.clone();

            tokio::spawn(async move {
                let settings =
                    Self::get_settings(client.clone(), uri.clone()).await;

                client.publish_diagnostics(PublishDiagnosticsParams {
                    uri: uri.clone(),
                    diagnostics: diagnostics(documents, uri, settings),
                    version: None,
                })
            });
        }
    }
}
