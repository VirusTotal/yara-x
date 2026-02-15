use async_lsp::{
    concurrency::ConcurrencyLayer, panic::CatchUnwindLayer,
    server::LifecycleLayer,
};
use futures::{AsyncRead, AsyncWrite};
use tower::ServiceBuilder;

use crate::server::YARALanguageServer;
use crate::tracing::MessageTracingLayer;

mod documents;
mod features;
mod server;
mod tracing;
mod utils;

#[cfg(test)]
mod tests;

/// Starts the Language Server Main Loop with provided streams.
///
/// Provided streams must implement [`futures::AsyncRead`] and
/// [`futures::AsyncWrite`] traits.
pub async fn serve(
    input: impl AsyncRead,
    output: impl AsyncWrite,
) -> Result<(), async_lsp::Error> {
    let (server, _) = async_lsp::MainLoop::new_server(|client| {
        ServiceBuilder::new()
            .layer(MessageTracingLayer)
            .layer(LifecycleLayer::default())
            .layer(CatchUnwindLayer::default())
            .layer(ConcurrencyLayer::default())
            .service(YARALanguageServer::new_router(client))
    });

    server.run_buffered(input, output).await
}
