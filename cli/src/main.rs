mod commands;
mod help;
mod walk;

use crossterm::tty::IsTty;
use std::{io, panic, process};
use yansi::Color::Red;
use yansi::Paint;

use crate::commands::cli;

const APP_HELP_TEMPLATE: &str = r#"{about-with-newline}
{author-with-newline}
{before-help}{usage-heading}
    {usage}

{all-args}{after-help}
"#;

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
        process::exit(1);
    }));

    let result = match args.subcommand() {
        Some(("debug", args)) => commands::exec_debug(args),
        Some(("check", args)) => commands::exec_check(args),
        Some(("fix", args)) => commands::exec_fix(args),
        Some(("fmt", args)) => commands::exec_fmt(args),
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
        match err.downcast_ref::<yara_x::Error>() {
            // Errors produced by the compiler already have colors and start
            // with "error:", in such cases the error is printed as is.
            Some(yara_x::Error::ParseError(_))
            | Some(yara_x::Error::CompileError(_)) => {
                eprintln!("{}", err);
            }
            // In all other cases imitate the style of compiler errors, so that
            // they all look in the same way.
            _ => {
                if let Some(source) = err.source() {
                    eprintln!(
                        "{} {}: {}",
                        "error:".paint(Red).bold(),
                        err,
                        source
                    );
                } else {
                    eprintln!("{} {}", "error:".paint(Red).bold(), err);
                }
            }
        }
        process::exit(1);
    }

    Ok(())
}
