mod commands;
mod help;
mod walk;

use clap::{command, crate_authors};
use yansi::Color::{Default, Red};

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

    let args = command!()
        .author(crate_authors!("\n")) // requires `cargo` feature
        .arg_required_else_help(true)
        .help_template(APP_HELP_TEMPLATE)
        .subcommands(vec![
            commands::scan(),
            commands::compile(),
            commands::ast(),
            commands::wasm(),
            commands::check(),
            commands::fmt(),
        ])
        .get_matches_from(wild::args());

    #[cfg(feature = "profiling")]
    let guard =
        pprof::ProfilerGuardBuilder::default().frequency(1000).build()?;

    let result = match args.subcommand() {
        Some(("ast", args)) => commands::exec_ast(args),
        Some(("wasm", args)) => commands::exec_wasm(args),
        Some(("check", args)) => commands::exec_check(args),
        Some(("fmt", args)) => commands::exec_fmt(args),
        Some(("scan", args)) => commands::exec_scan(args),
        Some(("compile", args)) => commands::exec_compile(args),
        _ => unreachable!(),
    };

    #[cfg(feature = "profiling")]
    if let Ok(report) = guard.report().build() {
        let file = std::fs::File::create("flamegraph.svg")?;
        report.flamegraph(file)?;
        println!("profiling information written to flamegraph.svg");
    };

    // Errors produced by the compiler already have colors and start with
    // "error:", in such cases the error is printed as is. In all other
    // cases imitate the style of compiler errors, so that they all look
    // in the same way.
    if let Err(err) = result {
        if err.is::<yara_x::Error>() {
            eprintln!("{}", err);
        } else {
            eprintln!(
                "{} {}",
                Red.paint("error:"),
                Default.style().bold().paint(err.to_string())
            );
            err.chain().skip(1).for_each(|cause| {
                eprintln!("\n{}\n    {}", Red.paint("caused by:"), cause)
            });
            std::process::exit(1);
        }
    }

    Ok(())
}
