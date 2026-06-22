use std::fs::{File, create_dir_all, write};
use std::io::Read;
use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgMatches, Command, arg, value_parser};
use yara_x::deep::Extractor;

use crate::help;

pub fn extract() -> Command {
    super::command("extract")
        .about("Extract data from container files")
        .long_about(help::EXTRACT_LONG_HELP)
        .arg(
            arg!(<FILE>)
                .help("Path to container file")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(<OUTPUT_DIR>)
                .help("Output directory where extracted files will be saved")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-d --"max-depth" <DEPTH>)
                .help("Maximum container extraction depth")
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )
}

pub fn exec_extract(args: &ArgMatches) -> anyhow::Result<()> {
    let file = args.get_one::<PathBuf>("FILE").unwrap();
    let output_dir = args.get_one::<PathBuf>("OUTPUT_DIR").unwrap();
    let max_depth = *args.get_one::<usize>("max-depth").unwrap_or(&1);

    let mut buffer = Vec::new();
    File::open(file)
        .with_context(|| format!("can not open `{}`", file.display()))?
        .read_to_end(&mut buffer)
        .with_context(|| format!("can not read `{}`", file.display()))?;

    let mut extractor = Extractor::new();
    extractor.max_depth(max_depth);

    let mut result = Ok(());

    let _ = extractor.extract(&buffer, |_module, path, bytes| {
        let target_path = output_dir.join(path);
        if let Some(parent) = target_path.parent()
            && let Err(err) = create_dir_all(parent)
        {
            result = Err(anyhow::Error::from(err).context(format!(
                "could not create directory `{}`",
                parent.display()
            )));
            return std::ops::ControlFlow::Break(());
        }
        if let Err(err) = write(&target_path, bytes) {
            result = Err(anyhow::Error::from(err).context(format!(
                "could not write file `{}`",
                target_path.display()
            )));
            return std::ops::ControlFlow::Break(());
        }
        std::ops::ControlFlow::Continue(())
    });

    result
}
