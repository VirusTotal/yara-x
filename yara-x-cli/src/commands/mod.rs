mod ast;
mod check;
mod compile;
mod fmt;
mod scan;
mod wasm;

pub use ast::*;
pub use check::*;
pub use compile::*;
pub use fmt::*;
pub use scan::*;
pub use wasm::*;

use std::fs;
use std::io::stdout;
use std::path::PathBuf;

use anyhow::Context;
use clap::Command;
use crossterm::tty::IsTty;

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

    for path in paths {
        w.walk(
            path,
            |file_path| {
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

                Ok(())
            },
            |err| eprintln!("{}", err),
        );
    }

    let rules = compiler.build();

    for warning in rules.warnings() {
        eprintln!("{}", warning);
    }

    Ok(rules)
}
