use crate::commands::cli;
use crate::help;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use clap_complete::{generate, Shell};
use std::io;

pub fn completion() -> Command {
    super::command("completion")
        .about("Output shell completion code for the specified shell")
        .long_about(help::COMPLETION_LONG_HELP)
        .arg(
            arg!(<SHELL>)
                .help("Shell name")
                .action(ArgAction::Set)
                .value_parser(value_parser!(Shell)),
        )
}

pub fn exec_completion(args: &ArgMatches) -> anyhow::Result<()> {
    if let Some(shell) = args.get_one::<Shell>("SHELL").cloned() {
        let mut cli = cli();
        generate(shell, &mut cli, "yr", &mut io::stdout());
    }
    Ok(())
}
