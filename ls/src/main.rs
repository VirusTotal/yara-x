#[cfg(target_family = "wasm")]
pub fn main() -> Result<(), async_lsp::Error> {
    panic!("this program can not run in WASM")
}

#[cfg(not(target_family = "wasm"))]
#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), async_lsp::Error> {
    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();

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

    yara_x_ls::serve(stdin, stdout).await
}
