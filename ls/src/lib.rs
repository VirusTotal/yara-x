use async_lsp::concurrency::ConcurrencyLayer;
use async_lsp::panic::CatchUnwindLayer;
use async_lsp::server::LifecycleLayer;

use futures::{AsyncRead, AsyncWrite};
use tower::ServiceBuilder;

use crate::server::ServerState;

#[cfg(test)]
mod tests;

mod features;
mod server;
mod utils;

pub use async_lsp::stdio;

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
            .layer(LifecycleLayer::default())
            .layer(CatchUnwindLayer::default())
            .layer(ConcurrencyLayer::default())
            .service(ServerState::new_router(client))
    });

    server.run_buffered(input, output).await
}
