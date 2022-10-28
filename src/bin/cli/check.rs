use anyhow::Context;
use globset::GlobMatcher;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use yansi::Color::Green;
use yara_x::parser::{Parser, SourceCode};

pub fn check_file(
    path: &Path,
    patterns: Option<&[GlobMatcher]>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(patterns) = patterns {
        if !patterns.iter().any(|p| p.is_match(path)) {
            return Ok(());
        }
    }

    let src = fs::read_to_string(path)
        .with_context(|| format!("can not read `{}`", path.display()))?;

    let src = SourceCode::from(src.as_str())
        .origin(path.as_os_str().to_str().unwrap());

    match Parser::new().colorize_errors(true).build_ast(src) {
        Ok(ast) => {
            if ast.warnings.is_empty() {
                println!("[{}] {}", Green.paint("ok"), path.display());
            } else {
                for warning in ast.warnings {
                    println!("\n{}", warning);
                }
            }
        }
        Err(err) => {
            println!("\n{}", err)
        }
    }

    Ok(())
}

pub fn check_dir(
    path: &Path,
    max_depth: u16,
    patterns: Option<&[GlobMatcher]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let walkdir = WalkDir::new(path).max_depth(max_depth as usize);
    for entry in walkdir.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        // The call to metadata can fail, for example when the directory
        // contains a symbolic link to a file that doesn't exist. We
        // simple ignore those error and continue.
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.is_file() {
                check_file(path, patterns)?
            }
        }
    }
    Ok(())
}
