use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wasm_opt::{Feature, OptimizationOptions};

const PKG_DIR: &str = "pkg";
const PKG_OUT_NAME: &str = "yara_x_js";
const NOMODULE_OUT_NAME: &str = "yara_x_js_bundle";
const WASM_RELEASE_OPT_LEVEL: &str = "z";

struct Config {
    out_dir: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_args(env::args_os())?;
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let pkg_dir = project_root.join(PKG_DIR);
    let dist_dir = project_root.join(&config.out_dir);
    let pkg_wasm_path = pkg_dir.join(format!("{PKG_OUT_NAME}_bg.wasm"));
    let dist_temp_js_path = dist_dir.join(format!("{PKG_OUT_NAME}.js"));
    let dist_temp_dts_path = dist_dir.join(format!("{PKG_OUT_NAME}.d.ts"));
    let dist_temp_wasm_path = dist_dir.join(format!("{PKG_OUT_NAME}_bg.wasm"));
    let dist_temp_wasm_dts_path =
        dist_dir.join(format!("{PKG_OUT_NAME}_bg.wasm.d.ts"));
    let dist_bundle_js_path = dist_dir.join(format!("{NOMODULE_OUT_NAME}.js"));
    let dist_bundle_dts_path =
        dist_dir.join(format!("{NOMODULE_OUT_NAME}.d.ts"));

    remove_dir_if_exists(&pkg_dir)?;
    remove_dir_if_exists(&dist_dir)?;

    build_wasm32_release(
        &project_root,
        Path::new(PKG_DIR),
        PKG_OUT_NAME,
        "web",
    )?;
    build_wasm32_release(
        &project_root,
        &config.out_dir,
        PKG_OUT_NAME,
        "no-modules",
    )?;
    optimize_wasm_file(&pkg_wasm_path)?;
    // `wasm-pack` drops `.gitignore` files into generated output directories
    // so the artifacts stay out of version control. Those files would also
    // cause `npm pack` to exclude the generated package contents, so strip
    // them after each build.
    remove_if_exists(&pkg_dir.join(".gitignore"))?;
    remove_if_exists(&dist_dir.join(".gitignore"))?;
    rename_if_exists(&dist_temp_js_path, &dist_bundle_js_path)?;
    rename_if_exists(&dist_temp_dts_path, &dist_bundle_dts_path)?;
    rewrite_bundle_default_wasm_path(&dist_bundle_js_path)?;
    append_browser_and_commonjs_exports(&dist_bundle_js_path)?;
    minify_js_bundle_with_terser(&dist_bundle_js_path)?;
    remove_if_exists(&dist_temp_wasm_path)?;
    remove_if_exists(&dist_temp_wasm_dts_path)?;
    remove_if_exists(&dist_dir.join(format!("{NOMODULE_OUT_NAME}.cjs")))?;
    eprintln!(
        "Built browser package in {} and bundle JS artifacts in {}",
        pkg_dir.display(),
        dist_dir.display(),
    );

    Ok(())
}

fn parse_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Config, Box<dyn Error>> {
    let mut out_dir = PathBuf::from("dist");

    let mut it = args.into_iter();
    let _ = it.next();

    while let Some(arg) = it.next() {
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

    Ok(Config { out_dir })
}

fn print_help() {
    eprintln!("build_web_release [--out-dir dist]");
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
    apply_wasm32_release_overrides(&mut cmd);

    run_command(&mut cmd)
}

fn apply_wasm32_release_overrides(cmd: &mut Command) {
    // Keep the size-focused release tuning scoped to the browser package build
    // instead of changing the whole workspace release profile.
    cmd.env("CARGO_PROFILE_RELEASE_OPT_LEVEL", WASM_RELEASE_OPT_LEVEL)
        .env("CARGO_PROFILE_RELEASE_LTO", "true")
        .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
        .env("CARGO_PROFILE_RELEASE_PANIC", "abort")
        .env("CARGO_PROFILE_RELEASE_STRIP", "symbols");
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

fn rewrite_bundle_default_wasm_path(
    js_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let original = std::fs::read_to_string(js_path)?;
    let from = "module_or_path = script_src.replace(/\\.js$/, \"_bg.wasm\");";
    let to = "module_or_path = new URL('../pkg/yara-x-wasm_bg.wasm', script_src).toString();";

    if !original.contains(from) {
        return Err(format!(
            "expected no-modules init path marker not found in {}",
            js_path.display()
        )
        .into());
    }

    let rewritten = original.replacen(from, to, 1);
    std::fs::write(js_path, rewritten)?;
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

fn rename_if_exists(from: &Path, to: &Path) -> Result<(), Box<dyn Error>> {
    if !from.exists() {
        return Err(
            format!("missing expected file: {}", from.display()).into()
        );
    }
    remove_if_exists(to)?;
    std::fs::rename(from, to)?;
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn optimize_wasm_file(path: &Path) -> Result<(), Box<dyn Error>> {
    if !path.exists() {
        return Err(
            format!("wasm artifact not found: {}", path.display()).into()
        );
    }

    let original_size = std::fs::metadata(path)?.len();
    let os_path = path.with_extension("os.wasm");
    let oz_path = path.with_extension("oz.wasm");

    build_wasm_opt_options(WasmOptProfile::Size).run(path, &os_path)?;
    build_wasm_opt_options(WasmOptProfile::SizeAggressive)
        .run(path, &oz_path)?;

    let os_size = std::fs::metadata(&os_path)?.len();
    let oz_size = std::fs::metadata(&oz_path)?.len();

    let (best_profile, best_path, best_size) =
        if os_size < original_size && os_size <= oz_size {
            ("-Os", Some(&os_path), os_size)
        } else if oz_size < original_size {
            ("-Oz", Some(&oz_path), oz_size)
        } else {
            ("original", None, original_size)
        };

    if let Some(best_path) = best_path {
        std::fs::rename(best_path, path)?;
    }

    if os_path.exists() {
        std::fs::remove_file(&os_path)?;
    }
    if oz_path.exists() {
        std::fs::remove_file(&oz_path)?;
    }

    eprintln!(
        "Selected {} for {} ({} -> {} bytes)",
        best_profile,
        path.display(),
        original_size,
        best_size
    );

    Ok(())
}

#[derive(Clone, Copy)]
enum WasmOptProfile {
    Size,
    SizeAggressive,
}

fn build_wasm_opt_options(profile: WasmOptProfile) -> OptimizationOptions {
    let mut opts = match profile {
        WasmOptProfile::Size => OptimizationOptions::new_optimize_for_size(),
        WasmOptProfile::SizeAggressive => {
            OptimizationOptions::new_optimize_for_size_aggressively()
        }
    };

    opts.enable_feature(Feature::Simd)
        .enable_feature(Feature::BulkMemory)
        .enable_feature(Feature::SignExt)
        .enable_feature(Feature::TruncSat)
        .enable_feature(Feature::ReferenceTypes)
        .enable_feature(Feature::Multivalue)
        .set_converge();

    opts
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
