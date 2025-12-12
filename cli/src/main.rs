mod commands;
mod config;
mod help;
mod walk;

#[cfg(test)]
mod tests;

use crossterm::tty::IsTty;
use home::home_dir;
use std::path::PathBuf;
use std::{io, panic, process};
use yansi::Color::Red;
use yansi::Paint;

use crate::commands::cli;
use crate::config::load_config_from_file;

const APP_HELP_TEMPLATE: &str = r#"YARA-X {version}, the pattern matching swiss army knife.

{author-with-newline}
{before-help}{usage-heading}
  {usage}

{all-args}{after-help}
"#;

const EXIT_ERROR: i32 = 1;
const CONFIG_FILE: &str = ".yara-x.toml";

fn main() -> anyhow::Result<()> {
    // Enable support for ANSI escape codes in Windows. In other platforms
    // this is a no-op.
    if let Err(err) = enable_ansi_support::enable_ansi_support() {
        println!("could not enable ANSI support: {err}")
    }

    #[cfg(feature = "logging")]
    env_logger::init();

    // If stdout is not a tty (for example, because it was redirected to a
    // file) turn off colors. This way you can redirect the output to a file
    // without ANSI escape codes messing up the file content.
    if !io::stdout().is_tty() {
        yansi::disable();
    }

    // Set our custom panic hook that kills the process when some panic
    // occurs in a thread. By default, when a thread panics the main thread
    // and all other threads keep running. We don't want that, we want the
    // process exiting as soon as any of the threads panics.
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        process::exit(EXIT_ERROR);
    }));

    let args = cli().get_matches_from(wild::args());

    // The config file is either the one specified by `--config` or
    // `$HOME/.yara-x.toml`. If the file does not exist, or $HOME is
    // empty, `config_file` will be `None`.
    let config_file = args
        .get_one::<PathBuf>("config")
        .cloned()
        .or_else(|| {
            home_dir()
                .filter(|dir| !dir.as_os_str().is_empty())
                .map(|dir| dir.join(CONFIG_FILE))
        })
        .filter(|file| file.exists());

    let config = config_file
        .map(|config_file| match load_config_from_file(&config_file) {
            Ok(config) => config,
            Err(err) => {
                eprintln!("{} {}", "error:".paint(Red).bold(), err);
                process::exit(EXIT_ERROR);
            }
        })
        .unwrap_or_default();

    let result = match args.subcommand() {
        #[cfg(feature = "debug-cmd")]
        Some(("debug", args)) => commands::exec_debug(args, &config),
        Some(("check", args)) => commands::exec_check(args, &config),
        Some(("fix", args)) => commands::exec_fix(args, &config),
        Some(("fmt", args)) => commands::exec_fmt(args, &config),
        Some(("scan", args)) => commands::exec_scan(args, &config),
        Some(("dump", args)) => commands::exec_dump(args),
        Some(("compile", args)) => commands::exec_compile(args, &config),
        Some(("completion", args)) => commands::exec_completion(args),
        _ => unreachable!(),
    };

    if let Err(err) = result {
        if let Some(source) = err.source() {
            eprintln!("{} {}: {}", "error:".paint(Red).bold(), err, source);
        } else {
            eprintln!("{} {}", "error:".paint(Red).bold(), err);
        }
        process::exit(EXIT_ERROR);
    }

    Ok(())
}
