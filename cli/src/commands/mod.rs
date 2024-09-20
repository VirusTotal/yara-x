mod check;
mod compile;
mod completion;
mod debug;
mod dump;
mod fix;
mod fmt;
mod scan;

pub use check::*;
pub use compile::*;
pub use completion::*;
#[cfg(feature = "debug-cmd")]
pub use debug::*;
pub use dump::*;
pub use fix::*;
pub use fmt::*;
pub use scan::*;

use std::borrow::Cow;
use std::fs;
use std::io::stdout;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use clap::{command, crate_authors, ArgMatches, Command};
use crossterm::tty::IsTty;
use superconsole::{Component, Line, Lines, Span, SuperConsole};
use yansi::Color::Green;
use yansi::Paint;

use crate::{commands, APP_HELP_TEMPLATE};
use yara_x::{Compiler, Rules, SourceCode};

use crate::walk::Walker;

pub fn command(name: &'static str) -> Command {
    Command::new(name).help_template(
        r#"{about-with-newline}
{usage-heading}
  {usage}

{all-args}
"#,
    )
}

pub fn cli() -> Command {
    command!()
        .author(crate_authors!("\n")) // requires `cargo` feature
        .arg_required_else_help(true)
        .help_template(APP_HELP_TEMPLATE)
        .subcommands(vec![
            commands::scan(),
            commands::compile(),
            commands::check(),
            #[cfg(feature = "debug-cmd")]
            commands::debug(),
            commands::dump(),
            commands::fmt(),
            commands::fix(),
            commands::completion(),
        ])
}

/// Parses the arguments to the `--define` option, which have the form
/// `VAR=VALUE`.
///
/// Returns the variable name and the value as a [`serde_json::Value`].
fn external_var_parser(
    option: &str,
) -> Result<(String, serde_json::Value), anyhow::Error> {
    let (var, value) = option.split_once('=').ok_or(anyhow!(
        "the equal sign is missing, use the syntax VAR=VALUE (example: {}=10)",
        option
    ))?;

    let value = serde_json::from_str(value).map_err(|_| {
        anyhow!(
            "`{}` is not a valid value, did you mean \\\"{}\\\"?",
            value,
            value
        )
    })?;

    Ok((var.to_string(), value))
}

/// Parses the argument to the `--module-data` option, which have the form
/// `MODULE=FILE`.
fn meta_file_value_parser(
    option: &str,
) -> Result<(String, PathBuf), anyhow::Error> {
    let (var, value) = option.split_once('=').ok_or(anyhow!(
        "the equal sign is missing, use the syntax MODULE=FILE (example: {}=file)",
        option
    ))?;

    let value = PathBuf::from(value);
    Ok((var.to_string(), value))
}

/// Parses a path prefixed by an optional namespace. Like this:
/// `[NAMESPACE:]PATH`.
///
/// Returns the namespace and the path. If the namespace is not provided
/// returns [`None`].
fn path_with_namespace_parser(
    input: &str,
) -> Result<(Option<String>, PathBuf), anyhow::Error> {
    if let Some((namespace, path)) = input.split_once(':') {
        Ok((Some(namespace.to_string()), PathBuf::from(path)))
    } else {
        Ok((None, PathBuf::from(input)))
    }
}

pub fn compile_rules<'a, P>(
    paths: P,
    external_vars: Option<Vec<(String, serde_json::Value)>>,
    args: &ArgMatches,
) -> Result<Rules, anyhow::Error>
where
    P: Iterator<Item = &'a (Option<String>, PathBuf)>,
{
    let mut compiler: Compiler<'_> = Compiler::new();

    compiler
        .relaxed_re_syntax(args.get_flag("relaxed-re-syntax"))
        .colorize_errors(stdout().is_tty());

    for m in args.get_many::<String>("ignore-module").into_iter().flatten() {
        compiler.ignore_module(m);
    }

    let disabled_warnings: Vec<_> = args
        .get_many::<String>("disable-warnings")
        .into_iter()
        .flatten()
        .collect();

    // If the `disabled_warnings` vector contains "all", all warnings will
    // be disabled. Otherwise, only the warnings with codes listed in
    // `disabled_warnings` will be disabled.
    if disabled_warnings.iter().any(|w| *w == "all") {
        compiler.switch_all_warnings(false);
    } else {
        for warning in &disabled_warnings {
            compiler.switch_warning(warning, false)?;
        }
    }

    if let Some(vars) = external_vars {
        for (ident, value) in vars {
            compiler.define_global(ident.as_str(), value)?;
        }
    }

    let mut console =
        if stdout().is_tty() { SuperConsole::new() } else { None };

    let mut state = CompileState::new();

    for (namespace, path) in paths {
        let mut w = Walker::path(path);

        w.filter("**/*.yar");
        w.filter("**/*.yara");

        compiler.new_namespace(
            namespace
                .as_ref()
                .map(|namespace| namespace.as_str())
                .unwrap_or("default"),
        );

        if let Err(err) = w.walk(
            |file_path| {
                state.file_in_progress = Some(file_path.into());

                if let Some(console) = console.as_mut() {
                    console.render(&state).unwrap();
                }

                let src = fs::read(file_path).with_context(|| {
                    format!("can not read `{}`", file_path.display())
                })?;

                let src = SourceCode::from(src.as_slice())
                    .with_origin(file_path.as_os_str().to_str().unwrap());

                if args.get_flag("path-as-namespace") {
                    compiler
                        .new_namespace(file_path.to_string_lossy().as_ref());
                }

                let _ = compiler.add_source(src);

                state.file_in_progress = None;

                state.num_compiled_files =
                    state.num_compiled_files.saturating_add(1);

                Ok(())
            },
            // Any error occurred during walk is aborts the walk.
            Err,
        ) {
            if let Some(console) = console {
                console.finalize(&state).unwrap();
            }
            return Err(err);
        }
    }

    if let Some(console) = console {
        console.finalize(&state).unwrap();
    }

    for error in compiler.errors() {
        eprintln!("{}", error);
    }

    for warning in compiler.warnings() {
        eprintln!("{}", warning);
    }

    if !compiler.errors().is_empty() {
        bail!("{} errors found", compiler.errors().len());
    }

    let rules = compiler.build();

    Ok(rules)
}

struct CompileState {
    num_compiled_files: usize,
    file_in_progress: Option<PathBuf>,
}

impl CompileState {
    fn new() -> Self {
        Self { num_compiled_files: 0, file_in_progress: None }
    }
}

impl Component for CompileState {
    fn draw_unchecked(
        &self,
        _dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<Lines> {
        let mut lines = Lines::new();

        if mode == superconsole::DrawMode::Normal {
            if let Some(file) = &self.file_in_progress {
                lines.push(Line::from_iter([Span::new_unstyled(format!(
                    "{} {}...",
                    "Compiling".paint(Green).bold(),
                    file.display(),
                ))?]));
            }
        }

        Ok(lines)
    }
}

fn truncate_with_ellipsis(s: Cow<str>, max_length: usize) -> Cow<str> {
    if s.len() <= max_length {
        s
    } else {
        format!("{}...", &s[..max_length - 3]).into()
    }
}
