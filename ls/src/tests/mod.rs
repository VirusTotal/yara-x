use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use async_lsp::{
    concurrency::ConcurrencyLayer,
    lsp_types::{
        notification::DidOpenTextDocument, ClientCapabilities,
        DiagnosticClientCapabilities, DidOpenTextDocumentParams,
        InitializeParams, InitializedParams, TextDocumentClientCapabilities,
        TextDocumentItem, Url,
    },
    router::Router,
    server::LifecycleLayer,
    LanguageServer, ServerSocket,
};
use futures::AsyncReadExt;
use serde::de::DeserializeOwned;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower::ServiceBuilder;

use crate::server::ServerState;

mod completion;
mod diagnostics;
mod document_highlights;
mod document_symbols;
mod goto;
mod hover;
mod references;
mod rename;
mod selection_range;

struct ClientState;

async fn start_server(
    path: &PathBuf,
) -> (ServerSocket, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let (server, _) = async_lsp::MainLoop::new_server(|_client| {
        ServiceBuilder::new()
            .layer(LifecycleLayer::default())
            .layer(ConcurrencyLayer::default())
            .service(ServerState::new_router(_client))
    });

    let (client, mut server_socket) =
        async_lsp::MainLoop::new_client(|_server| {
            let router = Router::new(ClientState {});
            ServiceBuilder::new().service(router)
        });

    let (client_stream, server_stream) = tokio::io::duplex(64000);

    let (client_rx, client_tx) = client_stream.compat().split();
    let client_thread = tokio::spawn(async move {
        let err = client.run_buffered(client_rx, client_tx).await.unwrap_err();
        assert!(
            matches!(err, async_lsp::Error::Eof),
            "Client exited with unexpected error: {err}",
        );
    });

    let (server_rx, server_tx) = server_stream.compat().split();
    let server_thread = tokio::spawn(async move {
        server.run_buffered(server_rx, server_tx).await.unwrap();
    });

    server_socket
        .initialize(InitializeParams {
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
        .unwrap();
    server_socket
        .initialized(InitializedParams {})
        .expect("Failed to initialize");

    let filename = path.file_name().unwrap().to_str().unwrap();
    let rule = fs::read_to_string(path).unwrap();

    server_socket
        .notify::<DidOpenTextDocument>(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: Url::parse(&format!("file:///{filename}")).unwrap(),
                language_id: "yara".to_string(),
                version: 1,
                text: rule,
            },
        })
        .expect("Failed to notify");
    (server_socket, client_thread, server_thread)
}

trait DeserializableTestDefinition {
    fn from_file(path: &PathBuf) -> Option<Self>
    where
        Self: DeserializeOwned,
    {
        let file = File::open(path).ok()?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).ok()
    }
}
