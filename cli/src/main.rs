mod commands;
mod config;
mod help;
mod walk;

use config::{load_config_from_file, Config};
use crossterm::tty::IsTty;
use std::{io, panic, process};
use yansi::Color::Red;
use yansi::Paint;

use crate::commands::cli;

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
        println!("could not enable ANSI support: {}", err)
    }

    #[cfg(feature = "logging")]
    env_logger::init();

    // If stdout is not a tty (for example, because it was redirected to a
    // file) turn off colors. This way you can redirect the output to a file
    // without ANSI escape codes messing up the file content.
    if !io::stdout().is_tty() {
        yansi::disable();
    }

    let args = cli().get_matches_from(wild::args());

    #[cfg(feature = "profiling")]
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        // Block these libs as advised in `pprof` documentation. Without this
        // it causes a deadlock in Linux.
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()?;

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

    let config: Config = match home::home_dir() {
        Some(home_path) if !home_path.as_os_str().is_empty() => {
            load_config_from_file(&home_path.join(CONFIG_FILE))
                .unwrap_or_default()
        }
        _ => Config::default(),
    };

    let result = match args.subcommand() {
        #[cfg(feature = "debug-cmd")]
        Some(("debug", args)) => commands::exec_debug(args),
        Some(("check", args)) => commands::exec_check(args),
        Some(("fix", args)) => commands::exec_fix(args),
        Some(("fmt", args)) => commands::exec_fmt(args, config.fmt),
        Some(("scan", args)) => commands::exec_scan(args),
        Some(("dump", args)) => commands::exec_dump(args),
        Some(("compile", args)) => commands::exec_compile(args),
        Some(("completion", args)) => commands::exec_completion(args),
        _ => unreachable!(),
    };

    #[cfg(feature = "profiling")]
    if let Ok(report) = guard.report().build() {
        let file = std::fs::File::create("flamegraph.svg")?;
        report.flamegraph(file)?;
        println!("profiling information written to flamegraph.svg");
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
