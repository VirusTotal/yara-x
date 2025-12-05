use clap::{ArgMatches, Command};
use yara_x_ls::{
    serve,
    stdio::{PipeStdin, PipeStdout},
};

pub fn language_server() -> Command {
    super::command("ls").about("Launch YARA-X Language Server")
}

#[tokio::main(flavor = "current_thread")]
pub async fn exec_language_server(_: &ArgMatches) -> anyhow::Result<()> {
    let (stdin, stdout) =
        (PipeStdin::lock_tokio()?, PipeStdout::lock_tokio()?);

    serve(stdin, stdout).await.map_err(|e| anyhow::anyhow!(e.to_string()))
}
