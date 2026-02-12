use std::fmt::Debug;
use std::fs;
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
    TextDocumentItem, Url, WorkspaceFolder,
};
use async_lsp::router::Router;
use async_lsp::server::LifecycleLayer;
use async_lsp::{LanguageServer, ServerSocket};
use futures::AsyncReadExt;
use serde_json::Value;
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
            let root_path = PathBuf::from("src/tests/testdata");
            let root_uri = Url::from_file_path(
                root_path.canonicalize().unwrap()
            ).unwrap();

            // Send request to initialize the server.
            server_socket
                .initialize(InitializeParams{
                    workspace_folders: Some(vec![WorkspaceFolder{
                        uri: root_uri,
                        name: "testdata".to_string(),
                    }]),
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
    let rule = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("failed to read file {path:?}"));

    s.notify::<DidOpenTextDocument>(DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: Url::from_file_path(path).unwrap(),
            language_id: "yara".to_string(),
            version: 1,
            text: rule,
        },
    })
    .expect("DidOpenTextDocument notification failed");
}

async fn close_document<P: AsRef<Path>>(s: &ServerSocket, path: P) {
    let path = path.as_ref();

    s.notify::<DidCloseTextDocument>(DidCloseTextDocumentParams {
        text_document: TextDocumentIdentifier {
            uri: Url::from_file_path(path).unwrap(),
        },
    })
    .expect("DidOpenTextDocument notification failed");
}

async fn test_lsp_request<P: AsRef<Path>, R: Request>(path: P)
where
    R::Result: serde::Serialize + serde::de::DeserializeOwned + Debug,
{
    let path = PathBuf::from("src/tests/testdata").join(path);
    let abs_path = path.canonicalize().unwrap();
    let test_dir = abs_path.parent().unwrap().to_str().unwrap();

    lsp_test(async |server_socket| {
        open_document(&server_socket, &abs_path).await;

        let mut mint = goldenfile::Mint::new(".");

        let request_path = path.with_extension("request.json");
        let request_str = fs::read_to_string(request_path.as_path())
            .unwrap_or_else(|_| panic!("can't read {request_path:?}"))
            .replace("${test_dir}", test_dir);

        let request = serde_json::from_str::<R::Params>(&request_str)
            .unwrap_or_else(|_| {
                panic!("failed to parse request: {}", request_str)
            });

        let response_path = path.with_extension("response.json");
        let response_file = mint
            .new_goldenfile(response_path.as_path())
            .unwrap_or_else(|_| panic!("can't read {request_path:?}"));

        let actual_response = match server_socket.request::<R>(request).await {
            Ok(response) => response,
            Err(err) => {
                panic!("request failed: {:?}", err)
            }
        };

        close_document(&server_socket, &abs_path).await;

        let mut response_json = serde_json::to_value(actual_response).unwrap();

        replace_in_json(&mut response_json, test_dir, "${test_dir}");
        serde_json::to_writer_pretty(response_file, &response_json).unwrap();
        server_socket
    })
    .await;
}

/// Replaces all occurrences of `from` with `to` in a JSON value.
///
/// This function recursively traverses the JSON value and performs the
/// replacement in string values and in object keys.

fn replace_in_json(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::Object(map) => {
            let keys_to_modify: Vec<(String, String)> = map
                .keys()
                .filter(|k| k.contains(from))
                .map(|k| (k.clone(), k.replace(from, to)))
                .collect();

            for (old_key, new_key) in keys_to_modify {
                if let Some(mut val) = map.remove(&old_key) {
                    replace_in_json(&mut val, from, to);
                    map.insert(new_key, val);
                }
            }

            for (_, val) in map.iter_mut() {
                replace_in_json(val, from, to);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                replace_in_json(v, from, to);
            }
        }
        Value::String(s) => {
            *s = s.replace(from, to);
        }
        _ => {}
    }
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
    test_lsp_request::<_, GotoDefinition>("goto6.yar").await;
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
