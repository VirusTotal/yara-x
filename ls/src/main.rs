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

/// Starts the Language Server Main Loop using Standard Input Output.
#[cfg(feature = "default")]
pub async fn serve_stdio() -> Result<(), async_lsp::Error> {
    #[cfg(unix)]
    let (stdin, stdout) = (
        async_lsp::stdio::PipeStdin::lock_tokio()?,
        async_lsp::stdio::PipeStdout::lock_tokio()?,
    );

    #[cfg(not(unix))]
    let (stdin, stdout) = (
        tokio_util::compat::TokioAsyncReadCompatExt::compat(tokio::io::stdin()),
        tokio_util::compat::TokioAsyncWriteCompatExt::compat_write(
            tokio::io::stdout(),
        ),
    );

    serve(stdin, stdout).await
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), async_lsp::Error> {
    serve_stdio().await
}
