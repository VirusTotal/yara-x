mod check;
mod compile;
mod debug;
mod fmt;
mod scan;

pub use check::*;
pub use compile::*;
pub use debug::*;
pub use fmt::*;
pub use scan::*;

use std::fs;
use std::io::stdout;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Context;
use clap::Command;
use crossterm::tty::IsTty;
use superconsole::{Component, Line, Lines, Span, SuperConsole};

use yara_x::{Compiler, Rules};
use yara_x_parser::SourceCode;

use crate::walk::DirWalker;

pub fn command(name: &'static str) -> Command {
    Command::new(name).help_template(
        r#"{about-with-newline}
{usage-heading}
    {usage}

{all-args}
"#,
    )
}

pub fn compile_rules<'a, P>(
    paths: P,
    path_as_namespace: bool,
) -> Result<Rules, anyhow::Error>
where
    P: Iterator<Item = &'a PathBuf>,
{
    let mut compiler: Compiler<'_> =
        Compiler::new().colorize_errors(stdout().is_tty());

    let mut w = DirWalker::new();

    w.filter("**/*.yar").filter("**/*.yara");

    let mut console =
        if stdout().is_tty() { SuperConsole::new() } else { None };

    let state = CompileState::new();

    for path in paths {
        if let Err(err) = w.walk(
            path,
            |file_path| {
                if let Some(console) = console.as_mut() {
                    console.render(&state).unwrap();
                }

                let src = fs::read(file_path).with_context(|| {
                    format!("can not read `{}`", file_path.display())
                })?;

                let src = SourceCode::from(src.as_slice())
                    .with_origin(file_path.as_os_str().to_str().unwrap());

                if path_as_namespace {
                    compiler
                        .new_namespace(file_path.to_string_lossy().as_ref());
                }

                compiler.add_source(src)?;
                state.num_compiled_files.fetch_add(1, Ordering::Relaxed);

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

    let rules = compiler.build();

    if let Some(console) = console {
        console.finalize(&state).unwrap();
    }

    for warning in rules.warnings() {
        eprintln!("\n{}", warning);
    }

    Ok(rules)
}

struct CompileState {
    num_compiled_files: AtomicUsize,
}

impl CompileState {
    fn new() -> Self {
        Self { num_compiled_files: AtomicUsize::new(0) }
    }
}

impl Component for CompileState {
    fn draw_unchecked(
        &self,
        dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<Lines> {
        let mut lines = Lines::new();

        if mode == superconsole::DrawMode::Normal {
            lines.push(Line::from_iter([Span::new_unstyled(
                "─".repeat(dimensions.width),
            )?]));

            lines.push(Line::from_iter([Span::new_unstyled(format!(
                " {} source file(s) compiled.",
                self.num_compiled_files.load(Ordering::Relaxed),
            ))?]));
        }

        Ok(lines)
    }
}
