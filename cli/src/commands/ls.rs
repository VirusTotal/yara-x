use clap::{ArgMatches, Command};
use yara_x_ls::serve_stdio;

pub fn language_server() -> Command {
    super::command("ls").about("Launch YARA-X Language Server")
}

#[tokio::main(flavor = "current_thread")]
pub async fn exec_language_server(_: &ArgMatches) -> anyhow::Result<()> {
    serve_stdio().await.map_err(|e| anyhow::anyhow!(e.to_string()))
}
