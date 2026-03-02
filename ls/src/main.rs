use yara_x_ls::serve;

/// Starts the Language Server Main Loop using Standard Input Output.
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
    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    serve_stdio().await
}
