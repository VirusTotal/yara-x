use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use wasm_opt::{Feature, OptimizationOptions};

const WASM32_TARGET: &str = "wasm32-unknown-unknown";
const WASM64_TARGET: &str = "wasm64-unknown-unknown";
const PKG_DIR: &str = "pkg";
const NOMODULE_OUT_NAME: &str = "yara_wasm_bundle";

struct Config {
    target: String,
    out_dir: PathBuf,
}

#[derive(Deserialize)]
struct CargoMetadata {
    target_directory: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_args(env::args_os())?;
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = cargo_target_dir(&project_root)?;

    match config.target.as_str() {
        WASM32_TARGET => {
            let pkg_dir = project_root.join(PKG_DIR);
            let dist_dir = project_root.join(&config.out_dir);

            remove_dir_if_exists(&pkg_dir)?;
            remove_dir_if_exists(&dist_dir)?;

            build_wasm32_release(
                &project_root,
                Path::new(PKG_DIR),
                "yara_wasm",
                "web",
            )?;
            build_wasm32_release(
                &project_root,
                &config.out_dir,
                NOMODULE_OUT_NAME,
                "no-modules",
            )?;
            // `wasm-pack` drops `.gitignore` files into generated output
            // directories so the artifacts stay out of version control. Those
            // files would also cause `npm pack` to exclude the generated
            // package contents, so strip them after each build.
            remove_if_exists(&pkg_dir.join(".gitignore"))?;
            remove_if_exists(&dist_dir.join(".gitignore"))?;
            append_browser_and_commonjs_exports(
                &dist_dir.join(format!("{NOMODULE_OUT_NAME}.js")),
            )?;
            minify_js_bundle_with_terser(
                &dist_dir.join(format!("{NOMODULE_OUT_NAME}.js")),
            )?;
            remove_if_exists(
                &dist_dir.join(format!("{NOMODULE_OUT_NAME}.cjs")),
            )?;
            eprintln!(
                "Built browser package in {} and bundle artifacts in {}",
                pkg_dir.display(),
                dist_dir.display(),
            );
        }
        WASM64_TARGET => {
            let wasm64_path = target_dir
                .join(WASM64_TARGET)
                .join("release")
                .join("yara_wasm.wasm");
            eprintln!(
                "Attempting experimental wasm64 release build (requires nightly + rust-src)."
            );
            build_wasm64_release(&project_root)?;
            if let Err(err) = optimize_wasm_file(&wasm64_path, true) {
                eprintln!(
                    "Skipping wasm64 optimization for {}: {err}",
                    wasm64_path.display()
                );
                eprintln!(
                    "The experimental wasm64 build completed, but the current wasm-opt toolchain could not optimize this module yet."
                );
            } else {
                eprintln!(
                    "Built + optimized wasm64 module at {}",
                    wasm64_path.display()
                );
            }
            eprintln!(
                "Note: wasm-bindgen JS glue for wasm64 may not be supported by your toolchain/runtime yet."
            );
        }
        _ => {
            return Err(format!(
                "unsupported target: {} (expected {} or {})",
                config.target, WASM32_TARGET, WASM64_TARGET
            )
            .into());
        }
    }

    Ok(())
}

fn parse_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Config, Box<dyn Error>> {
    let mut target = WASM32_TARGET.to_owned();
    let mut out_dir = PathBuf::from("dist");

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
            continue;
        }

        if arg == "--out-dir" {
            let Some(value) = it.next() else {
                return Err("--out-dir requires a value".into());
            };
            out_dir = PathBuf::from(value);
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

    Ok(Config { target, out_dir })
}

fn print_help() {
    eprintln!(
        "build_web_release [--target wasm32-unknown-unknown|wasm64-unknown-unknown] [--out-dir dist]"
    );
}

fn cargo_target_dir(project_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(project_root)
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

fn build_wasm32_release(
    project_root: &Path,
    out_dir: &Path,
    out_name: &str,
    target: &str,
) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new("wasm-pack");
    cmd.current_dir(project_root)
        .arg("build")
        .arg("--target")
        .arg(target)
        .arg("--release")
        .arg("--mode")
        .arg("no-install")
        .arg("--no-pack")
        .arg("--no-opt")
        .arg("--out-dir")
        .arg(out_dir)
        .arg("--out-name")
        .arg(out_name);

    run_command(&mut cmd)
}

fn build_wasm64_release(project_root: &Path) -> Result<(), Box<dyn Error>> {
    let mut rustup = Command::new("rustup");
    rustup
        .current_dir(project_root)
        .arg("component")
        .arg("add")
        .arg("rust-src")
        .arg("--toolchain")
        .arg("nightly");
    run_command(&mut rustup)?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(project_root)
        .arg("+nightly")
        .arg("build")
        .arg("-Zbuild-std=std,panic_abort")
        .arg("--target")
        .arg(WASM64_TARGET)
        .arg("--release")
        .env("RUSTFLAGS", merged_wasm64_rustflags());

    run_command(&mut cmd)
}

fn append_browser_and_commonjs_exports(
    js_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().append(true).open(js_path)?;
    file.write_all(
        br#"
;(() => {
  const root =
    typeof globalThis !== "undefined"
      ? globalThis
      : typeof self !== "undefined"
        ? self
        : typeof window !== "undefined"
          ? window
          : this;

  if (typeof module === "object" && module && module.exports) {
    module.exports = wasm_bindgen;
  }

  root.YaraWasm = wasm_bindgen;
})();
"#,
    )?;
    Ok(())
}

fn minify_js_bundle_with_terser(path: &Path) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or_else(|| {
        format!("missing parent directory for {}", path.display())
    })?;
    let js_name =
        path.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
            format!("invalid js filename for {}", path.display())
        })?;
    let js_stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid js stem for {}", path.display()))?;

    let min_js_name = format!("{js_stem}.min.js");
    let min_js_path = parent.join(&min_js_name);
    let min_map_path = parent.join(format!("{js_stem}.min.js.map"));
    let map_url = min_map_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "invalid source map filename for {}",
                min_map_path.display()
            )
        })?;
    let source_map_arg = format!("filename={min_js_name},url={map_url}");

    // Clean up stale artifacts so each build has deterministic outputs.
    remove_if_exists(&min_js_path)?;
    remove_if_exists(&min_map_path)?;
    remove_if_exists(&path.with_extension("js.map"))?;

    let mut cmd = Command::new("terser");
    cmd.current_dir(parent)
        .arg(js_name)
        .arg("--compress")
        .arg("--mangle")
        .arg("keep_fnames=true,keep_classnames=true")
        .arg("--source-map")
        .arg(source_map_arg)
        .arg("--output")
        .arg(&min_js_name);
    run_command(&mut cmd)?;
    if !min_js_path.exists() {
        return Err(format!(
            "terser did not produce expected minified output: {}",
            min_js_path.display()
        )
        .into());
    }
    if !min_map_path.exists() {
        return Err(format!(
            "terser did not produce expected source map: {}",
            min_map_path.display()
        )
        .into());
    }

    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn optimize_wasm_file(
    path: &Path,
    memory64: bool,
) -> Result<(), Box<dyn Error>> {
    if !path.exists() {
        return Err(
            format!("wasm artifact not found: {}", path.display()).into()
        );
    }

    let optimized_path = path.with_extension("opt.wasm");

    let mut opts = OptimizationOptions::new_opt_level_4();
    opts.enable_feature(Feature::Simd)
        .enable_feature(Feature::BulkMemory)
        .enable_feature(Feature::SignExt)
        .enable_feature(Feature::ReferenceTypes)
        .enable_feature(Feature::Multivalue)
        .set_converge();

    if memory64 {
        opts.enable_feature(Feature::Memory64);
    }

    opts.run(path, &optimized_path)?;
    std::fs::rename(&optimized_path, path)?;

    Ok(())
}

fn merged_wasm64_rustflags() -> String {
    let existing = env::var("RUSTFLAGS").unwrap_or_default();
    let mut flags = existing;

    for required_flag in [
        "-C target-feature=+simd128",
        r#"--cfg getrandom_backend="unsupported""#,
    ] {
        if flags.contains(required_flag) {
            continue;
        }

        // The experimental wasm64 build pulls in `getrandom` transitively, but
        // upstream does not offer a wasm64 backend yet. Use the explicit
        // `unsupported` backend so the build can still succeed until the target
        // gains proper support.
        if flags.trim().is_empty() {
            flags = required_flag.to_owned();
        } else {
            flags.push(' ');
            flags.push_str(required_flag);
        }
    }

    flags
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
