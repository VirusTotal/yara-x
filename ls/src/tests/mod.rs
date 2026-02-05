use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::future::Future;
use std::path::{Path, PathBuf};

use async_lsp::concurrency::ConcurrencyLayer;
use async_lsp::lsp_types::notification::{
    DidCloseTextDocument, DidOpenTextDocument,
};
use async_lsp::lsp_types::request::{
    CodeActionRequest, Completion, DocumentDiagnosticRequest,
    DocumentHighlightRequest, DocumentSymbolRequest, Formatting,
    GotoDefinition, HoverRequest, References, Rename, Request,
    SelectionRangeRequest, SemanticTokensFullRequest,
    SemanticTokensRangeRequest,
};
use async_lsp::lsp_types::{
    ClientCapabilities, DiagnosticClientCapabilities,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, InitializeParams,
    InitializedParams, TextDocumentClientCapabilities, TextDocumentIdentifier,
    TextDocumentItem, Url,
};
use async_lsp::router::Router;
use async_lsp::server::LifecycleLayer;
use async_lsp::{LanguageServer, ServerSocket};
use futures::AsyncReadExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower::ServiceBuilder;

use crate::server::YARALanguageServer;

struct ClientState;

async fn lsp_test<F, R>(f: F)
where
    R: Future<Output = ServerSocket>,
    F: Fn(ServerSocket) -> R,
{
    let (server, _) = async_lsp::MainLoop::new_server(|client| {
        ServiceBuilder::new()
            .layer(LifecycleLayer::default())
            .layer(ConcurrencyLayer::default())
            .service(YARALanguageServer::new_router(client))
    });

    let (client, mut server_socket) =
        async_lsp::MainLoop::new_client(|_server| {
            let router = Router::new(ClientState {});
            ServiceBuilder::new().service(router)
        });

    let (client_stream, server_stream) = tokio::io::duplex(64000);

    let (client_rx, client_tx) = client_stream.compat().split();
    let (server_rx, server_tx) = server_stream.compat().split();

    tokio::select! {
        _ = server.run_buffered(server_rx, server_tx) => {}
        _ = client.run_buffered(client_rx, client_tx) => {}
        _ = async {
            // Send request to initialize the server.
            server_socket
                .initialize(InitializeParams{
                     capabilities: ClientCapabilities {
                         text_document: Some(TextDocumentClientCapabilities {
                             diagnostic: Some(DiagnosticClientCapabilities {
                                 dynamic_registration: Some(true),
                                 ..Default::default()
                             }),
                             ..Default::default()
                         }),
                         ..Default::default()
                     },
                     ..Default::default()
                 })
                .await
                .expect("failed to initialize the LSP");

            // Send notification that tells the server that the client has
            // received the result of the initialization request.
            server_socket
                .initialized(InitializedParams{})
                .expect("failed to notify the server that the client was initialized");

            f(server_socket).await.shutdown(()).await.expect("server shutdown");
        } => {}
    }
}

async fn open_document<P: AsRef<Path>>(s: &ServerSocket, path: P) {
    let path = path.as_ref();
    let filename = path.file_name().unwrap().to_str().unwrap();
    let rule = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("failed to read file {path:?}"));

    s.notify::<DidOpenTextDocument>(DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: Url::parse(format!("file:///{filename}").as_str()).unwrap(),
            language_id: "yara".to_string(),
            version: 1,
            text: rule,
        },
    })
    .expect("DidOpenTextDocument notification failed");
}

async fn close_document<P: AsRef<Path>>(s: &ServerSocket, path: P) {
    let path = path.as_ref();
    let filename = path.file_name().unwrap().to_str().unwrap();

    s.notify::<DidCloseTextDocument>(DidCloseTextDocumentParams {
        text_document: TextDocumentIdentifier {
            uri: Url::parse(format!("file:///{filename}").as_str()).unwrap(),
        },
    })
    .expect("DidOpenTextDocument notification failed");
}

async fn test_lsp_request<P: AsRef<Path>, R: Request>(path: P)
where
    R::Result: serde::Serialize + serde::de::DeserializeOwned + Debug,
{
    let path = PathBuf::from("src/tests/testdata").join(path);

    lsp_test(async |server_socket| {
        open_document(&server_socket, path.as_path()).await;

        let mut mint = goldenfile::Mint::new(".");

        let request_path = path.with_extension("request.json");
        let request_file = File::open(request_path.as_path())
            .unwrap_or_else(|_| panic!("can't read {request_path:?}"));

        let response_path = path.with_extension("response.json");
        let response_file = mint
            .new_goldenfile(response_path.as_path())
            .unwrap_or_else(|_| panic!("can't read {request_path:?}"));

        let request =
            serde_json::from_reader::<_, R::Params>(request_file).unwrap();

        let actual_response =
            server_socket.request::<R>(request).await.unwrap();

        close_document(&server_socket, path.as_path()).await;

        serde_json::to_writer_pretty(response_file, &actual_response).unwrap();
        server_socket
    })
    .await;
}

#[tokio::test]
async fn selection_range() {
    test_lsp_request::<_, SelectionRangeRequest>("selectionrange1.yar").await;
    test_lsp_request::<_, SelectionRangeRequest>("selectionrange2.yar").await;
    test_lsp_request::<_, SelectionRangeRequest>("selectionrange3.yar").await;
    test_lsp_request::<_, SelectionRangeRequest>("selectionrange4.yar").await;
    test_lsp_request::<_, SelectionRangeRequest>("selectionrange5.yar").await;
    test_lsp_request::<_, SelectionRangeRequest>("selectionrange6.yar").await;
    test_lsp_request::<_, SelectionRangeRequest>("selectionrange7.yar").await;
}

#[tokio::test]
async fn rename() {
    test_lsp_request::<_, Rename>("rename1.yar").await;
    test_lsp_request::<_, Rename>("rename2.yar").await;
    test_lsp_request::<_, Rename>("rename3.yar").await;
    test_lsp_request::<_, Rename>("rename4.yar").await;
    test_lsp_request::<_, Rename>("rename5.yar").await;
}

#[tokio::test]
async fn references() {
    test_lsp_request::<_, References>("references1.yar").await;
    test_lsp_request::<_, References>("references2.yar").await;
    test_lsp_request::<_, References>("references3.yar").await;
    test_lsp_request::<_, References>("references4.yar").await;
    test_lsp_request::<_, References>("references5.yar").await;
}

#[tokio::test]
async fn goto_definition() {
    test_lsp_request::<_, GotoDefinition>("goto1.yar").await;
    test_lsp_request::<_, GotoDefinition>("goto2.yar").await;
    test_lsp_request::<_, GotoDefinition>("goto3.yar").await;
    test_lsp_request::<_, GotoDefinition>("goto4.yar").await;
    test_lsp_request::<_, GotoDefinition>("goto5.yar").await;
}

#[tokio::test]
async fn hover() {
    test_lsp_request::<_, HoverRequest>("hover1.yar").await;
    test_lsp_request::<_, HoverRequest>("hover2.yar").await;
    test_lsp_request::<_, HoverRequest>("hover3.yar").await;
    test_lsp_request::<_, HoverRequest>("hover4.yar").await;
    test_lsp_request::<_, HoverRequest>("hover5.yar").await;
    test_lsp_request::<_, HoverRequest>("hover6.yar").await;
    test_lsp_request::<_, HoverRequest>("hover7.yar").await;
}

#[tokio::test]
async fn document_symbols() {
    test_lsp_request::<_, DocumentSymbolRequest>("symbols1.yar").await;
    test_lsp_request::<_, DocumentSymbolRequest>("symbols2.yar").await;
    test_lsp_request::<_, DocumentSymbolRequest>("symbols3.yar").await;
    test_lsp_request::<_, DocumentSymbolRequest>("symbols4.yar").await;
    test_lsp_request::<_, DocumentSymbolRequest>("symbols5.yar").await;
    test_lsp_request::<_, DocumentSymbolRequest>("symbols6.yar").await;
    test_lsp_request::<_, DocumentSymbolRequest>("symbols7.yar").await;
}

#[tokio::test]
async fn document_highlights() {
    test_lsp_request::<_, DocumentHighlightRequest>("highlights1.yar").await;
    test_lsp_request::<_, DocumentHighlightRequest>("highlights2.yar").await;
    test_lsp_request::<_, DocumentHighlightRequest>("highlights3.yar").await;
    test_lsp_request::<_, DocumentHighlightRequest>("highlights4.yar").await;
    test_lsp_request::<_, DocumentHighlightRequest>("highlights5.yar").await;
}

#[tokio::test]
async fn document_diagnostics() {
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics1.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics2.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics3.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics4.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics5.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics6.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics7.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, DocumentDiagnosticRequest>("diagnostics8.yar").await;
}

#[tokio::test]
async fn completion() {
    test_lsp_request::<_, Completion>("completion1.yar").await;
    test_lsp_request::<_, Completion>("completion2.yar").await;
    test_lsp_request::<_, Completion>("completion3.yar").await;
    test_lsp_request::<_, Completion>("completion4.yar").await;
    test_lsp_request::<_, Completion>("completion5.yar").await;
    test_lsp_request::<_, Completion>("completion6.yar").await;
    test_lsp_request::<_, Completion>("completion7.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, Completion>("completion8.yar").await;

    #[cfg(feature = "full-compiler")]
    test_lsp_request::<_, Completion>("completion9.yar").await;

    #[cfg(all(feature = "full-compiler", not(feature = "magic-module")))]
    test_lsp_request::<_, Completion>("completion10.yar").await;

    #[cfg(all(feature = "full-compiler", not(feature = "magic-module")))]
    test_lsp_request::<_, Completion>("completion11.yar").await;

    #[cfg(all(feature = "full-compiler", not(feature = "magic-module")))]
    test_lsp_request::<_, Completion>("completion12.yar").await;

    #[cfg(all(feature = "full-compiler", not(feature = "magic-module")))]
    test_lsp_request::<_, Completion>("completion13.yar").await;
}

#[tokio::test]
async fn formatting() {
    test_lsp_request::<_, Formatting>("formatting1.yar").await;
}

#[tokio::test]
async fn code_action() {
    test_lsp_request::<_, CodeActionRequest>("code_action.yar").await;
}

#[tokio::test]
async fn semantic_tokens() {
    test_lsp_request::<_, SemanticTokensFullRequest>("semantic_tokens1.yar")
        .await;

    test_lsp_request::<_, SemanticTokensFullRequest>("semantic_tokens2.yar")
        .await;
}

#[tokio::test]
async fn semantic_tokens_range() {
    test_lsp_request::<_, SemanticTokensRangeRequest>(
        "semantic_tokens_range.yar",
    )
    .await;
}
