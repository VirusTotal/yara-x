use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use wasm_opt::{Feature, OptimizationOptions};

const DEFAULT_TARGET: &str = "wasm32-wasip1";
const DEFAULT_OUT_DIR: &str = "release";
const MEMORY64_TARGET: &str = "wasm64-unknown-unknown";
const MEMORY64_OUT_DIR: &str = "release-memory64";
const MEMORY64_PROFILING_OUT_DIR: &str = "release-memory64-profiling";
const GUEST_BIN: &str = "yarax_guest";
const NIGHTLY_TOOLCHAIN: &str = "nightly";

struct Config {
    target: String,
    out_dir: PathBuf,
    features: Vec<String>,
    toolchain: Option<String>,
    build_std: bool,
    memory64: bool,
}

#[derive(Deserialize)]
struct CargoMetadata {
    target_directory: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_args(env::args_os())?;
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = cargo_target_dir(&crate_dir)?;

    ensure_build_prerequisites(&crate_dir, &config)?;
    build_guest_release(&crate_dir, &config)?;

    let built_wasm = target_dir
        .join(&config.target)
        .join("release")
        .join(format!("{GUEST_BIN}.wasm"));

    if !built_wasm.exists() {
        return Err(format!(
            "wasm artifact not found: {}",
            built_wasm.display()
        )
        .into());
    }

    let out_dir = crate_dir.join(&config.out_dir);
    std::fs::create_dir_all(&out_dir)?;
    let out_wasm = out_dir.join(format!("{GUEST_BIN}.wasm"));

    optimize_wasm_file(&built_wasm, &out_wasm, config.memory64)?;

    eprintln!("built + optimized guest module at {}", out_wasm.display());

    Ok(())
}

fn parse_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Config, Box<dyn Error>> {
    let mut target = DEFAULT_TARGET.to_owned();
    let mut target_overridden = false;
    let mut out_dir = PathBuf::from(DEFAULT_OUT_DIR);
    let mut out_dir_overridden = false;
    let mut features = Vec::new();
    let mut profiling = false;
    let mut memory64 = false;

    let mut it = args.into_iter();
    let _ = it.next();

    while let Some(arg) = it.next() {
        if arg == "--target" {
            let Some(value) = it.next() else {
                return Err("--target requires a value".into());
            };
            target = value
                .into_string()
                .map_err(|_| "--target must be valid UTF-8")?;
            target_overridden = true;
            continue;
        }

        if arg == "--out-dir" {
            let Some(value) = it.next() else {
                return Err("--out-dir requires a value".into());
            };
            out_dir = PathBuf::from(value);
            out_dir_overridden = true;
            continue;
        }

        if arg == "--features" {
            let Some(value) = it.next() else {
                return Err("--features requires a value".into());
            };
            let raw = value
                .into_string()
                .map_err(|_| "--features must be valid UTF-8")?;
            for feature in
                raw.split(',').map(str::trim).filter(|s| !s.is_empty())
            {
                features.push(feature.to_owned());
            }
            continue;
        }

        if arg == "--profiling" {
            profiling = true;
            features.push("rules-profiling".to_owned());
            continue;
        }

        if arg == "--memory64" {
            memory64 = true;
            continue;
        }

        if arg == "--help" || arg == "-h" {
            print_help();
            std::process::exit(0);
        }

        return Err(
            format!("unknown argument: {}", arg.to_string_lossy()).into()
        );
    }

    if target == MEMORY64_TARGET {
        memory64 = true;
    }

    if memory64 {
        if target_overridden && target != MEMORY64_TARGET {
            return Err(format!(
                "--memory64 requires --target {MEMORY64_TARGET}, got {target}"
            )
            .into());
        }
        target = MEMORY64_TARGET.to_owned();
    }

    if !out_dir_overridden {
        out_dir = match (memory64, profiling) {
            (true, true) => PathBuf::from(MEMORY64_PROFILING_OUT_DIR),
            (true, false) => PathBuf::from(MEMORY64_OUT_DIR),
            (false, true) => PathBuf::from("release-profiling"),
            (false, false) => PathBuf::from(DEFAULT_OUT_DIR),
        };
    }

    let toolchain = memory64.then(|| NIGHTLY_TOOLCHAIN.to_owned());
    let build_std = memory64;

    Ok(Config { target, out_dir, features, toolchain, build_std, memory64 })
}

fn print_help() {
    eprintln!(
        "build_web_release [--target wasm32-wasip1] [--out-dir release] [--features a,b] [--profiling] [--memory64]"
    );
}

fn cargo_target_dir(crate_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(crate_dir)
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps");

    let output = cmd.output()?;

    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed with status {}",
            output.status
        )
        .into());
    }

    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)?;
    Ok(metadata.target_directory)
}

fn ensure_build_prerequisites(
    crate_dir: &Path,
    config: &Config,
) -> Result<(), Box<dyn Error>> {
    if let Some(toolchain) = config.toolchain.as_deref() {
        ensure_rustup_component(crate_dir, toolchain, "rust-src")?;
    }

    if !config.build_std {
        ensure_target_installed(
            crate_dir,
            config.toolchain.as_deref(),
            &config.target,
        )?;
    }

    Ok(())
}

fn ensure_target_installed(
    crate_dir: &Path,
    toolchain: Option<&str>,
    target: &str,
) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new("rustup");
    cmd.current_dir(crate_dir);
    if let Some(toolchain) = toolchain {
        cmd.arg(format!("+{toolchain}"));
    }
    cmd.arg("target").arg("add").arg(target);
    run_command(&mut cmd)
}

fn ensure_rustup_component(
    crate_dir: &Path,
    toolchain: &str,
    component: &str,
) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new("rustup");
    cmd.current_dir(crate_dir)
        .arg("component")
        .arg("add")
        .arg(component)
        .arg("--toolchain")
        .arg(toolchain);
    run_command(&mut cmd)
}

fn build_guest_release(
    crate_dir: &Path,
    config: &Config,
) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(crate_dir);

    if let Some(toolchain) = config.toolchain.as_deref() {
        cmd.arg(format!("+{toolchain}"));
    }

    cmd.arg("build")
        .arg("--release")
        .arg("--target")
        .arg(&config.target)
        .arg("--bin")
        .arg(GUEST_BIN)
        .env("RUSTFLAGS", merged_guest_rustflags(config.memory64))
        .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
        .env("CARGO_PROFILE_RELEASE_LTO", "thin")
        .env("CARGO_PROFILE_RELEASE_PANIC", "abort");

    if config.build_std {
        cmd.arg("-Z").arg("build-std=std,panic_abort");
    }

    if !config.features.is_empty() {
        cmd.arg("--features").arg(config.features.join(","));
    }

    if config.memory64 {
        eprintln!(
            "building experimental memory64 guest with nightly Rust; this path depends on still-evolving upstream wasm64 support"
        );
    }

    if let Err(err) = run_command(&mut cmd) {
        if config.memory64 {
            return Err(format!(
                "experimental memory64 guest build failed: {err}. Current upstream Rust/WIT support for wasm64 may still be incomplete; wit-bindgen currently blocks some guest configurations because `cabi-realloc` support is still wasm32-only"
            )
            .into());
        }
        return Err(err);
    }

    Ok(())
}

fn optimize_wasm_file(
    input: &Path,
    output: &Path,
    memory64: bool,
) -> Result<(), Box<dyn Error>> {
    if output.exists() {
        std::fs::remove_file(output)?;
    }

    let mut opts = OptimizationOptions::new_opt_level_4();
    opts.enable_feature(Feature::BulkMemory)
        .enable_feature(Feature::ReferenceTypes)
        .enable_feature(Feature::Multivalue)
        .enable_feature(Feature::Simd)
        .enable_feature(Feature::SignExt)
        .set_converge();

    if memory64 {
        opts.enable_feature(Feature::Memory64);
    }

    opts.run(input, output)?;
    Ok(())
}

fn merged_guest_rustflags(_memory64: bool) -> String {
    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    append_rustflag(&mut rustflags, "-C target-feature=+simd128");
    rustflags
}

fn append_rustflag(rustflags: &mut String, flag: &str) {
    if rustflags.contains(flag) {
        return;
    }
    if !rustflags.trim().is_empty() {
        rustflags.push(' ');
    }
    rustflags.push_str(flag);
}

fn run_command(cmd: &mut Command) -> Result<(), Box<dyn Error>> {
    eprintln!("running: {:?}", cmd);
    let status = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !status.success() {
        return Err(format!("command failed with status {status}").into());
    }

    Ok(())
}
