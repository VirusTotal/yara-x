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

pub fn command(name: &'static str) -> Command {
    Command::new(name).help_template(
        r#"{about-with-newline}
{usage-heading}
    {usage}

{all-args}
"#,
    )
}

fn compile_rules<'a, P>(
    paths: P,
    path_as_namespace: bool,
) -> Result<Rules, anyhow::Error>
where
    P: Iterator<Item = &'a PathBuf>,
{
    let mut compiler = Compiler::new().colorize_errors(stdout().is_tty());

    for path in paths {
        let src = fs::read(path)
            .with_context(|| format!("can not read `{}`", path.display()))?;

        let src = SourceCode::from(src.as_slice())
            .origin(path.as_os_str().to_str().unwrap());

        if path_as_namespace {
            compiler = compiler.new_namespace(path.to_string_lossy().as_ref());
        }

        compiler = compiler.add_source(src)?;
    }

    for warning in compiler.warnings() {
        println!("{}", warning);
    }

    Ok(compiler.build())
}
