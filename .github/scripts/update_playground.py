
#!/usr/bin/env python3
"""Update the YARA-X playground from a published release.

Usage: python3 .github/scripts/update_playground.py 1.22.0
Requires Python 3.11+, Rust, wasm32-unknown-unknown, Node.js and npm.
"""

import argparse
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAYGROUND = ROOT / "playground"
LS_PACKAGE = PLAYGROUND / "src/wasm/yara-x-ls/pkg"
LS_FILES = (
    "yara_x_ls.js",
    "yara_x_ls.d.ts",
    "yara_x_ls_bg.wasm",
    "yara_x_ls_bg.wasm.d.ts",
)


def run(*command: str | Path, cwd: Path = ROOT) -> None:
    args = [str(arg) for arg in command]
    print(f"\n$ {shlex.join(args)}", flush=True)
    subprocess.run(args, cwd=cwd, check=True)


def parse_version(value: str) -> str:
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", value):
        raise argparse.ArgumentTypeError("Expected 1.22.0 or v1.22.0")
    return value.removeprefix("v")


def verify_npm_release(version: str) -> None:
    package = f"@virustotal/yara-x@{version}"
    result = subprocess.run(
        ["npm", "view", package, "version"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise ValueError(
            f"Cannot verify {package} on npm: {result.stderr.strip()}"
        )

    if result.stdout.strip() != version:
        raise ValueError(
            f"Expected npm version {version}, got {result.stdout.strip()!r}"
        )

    print(f"npm release found: {package}", flush=True)


def fetch_release(version: str, directory: Path) -> Path:
    source = directory / "source"

    run(
        "git", "clone", "--depth", "1", "--branch", f"v{version}",
        "--single-branch", "https://github.com/VirusTotal/yara-x.git",
        source,
    )

    manifest_path = source / "ls/Cargo.toml"

    if not manifest_path.is_file():
        raise ValueError(
            f"Release v{version} does not include the Language Server"
        )

    manifest = tomllib.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    if manifest["package"]["name"] != "yara-x-ls":
        raise ValueError(
            f"Release v{version} does not contain yara-x-ls"
        )

    return source


def wasm_bindgen_version(source: Path) -> str:
    lockfile = tomllib.loads(
        (source / "Cargo.lock").read_text(encoding="utf-8")
    )

    for package in lockfile["package"]:
        if package["name"] == "wasm-bindgen":
            return package["version"]

    raise ValueError("wasm-bindgen not found in Cargo.lock")


def build_language_server(source: Path) -> Path:
    run(
        "cargo", "build",
        "--target", "wasm32-unknown-unknown",
        "--no-default-features",
        "-p", "yara-x-ls", "--lib",
        "--release", "--locked",
        cwd=source,
    )

    return source / "target/wasm32-unknown-unknown/release/yara_x_ls.wasm"


def generate_bindings(
    source: Path, wasm: Path, directory: Path
) -> Path:
    tools = directory / "tools"

    run(
        "cargo", "install", "wasm-bindgen-cli", "--locked",
        "--version", wasm_bindgen_version(source),
        "--root", tools,
    )

    output = directory / "bindings"

    run(
        tools / "bin/wasm-bindgen", wasm,
        "--target", "web",
        "--out-dir", output,
    )

    for filename in LS_FILES:
        if not (output / filename).is_file():
            raise ValueError(f"Missing generated LS file: {filename}")

    return output


def update_playground(version: str, bindings: Path) -> None:
    run(
        "npm", "install", "--save-exact",
        f"@virustotal/yara-x@{version}",
        cwd=PLAYGROUND,
    )

    LS_PACKAGE.mkdir(parents=True, exist_ok=True)

    for filename in LS_FILES:
        shutil.copyfile(bindings / filename, LS_PACKAGE / filename)

    run("npm", "run", "format", cwd=PLAYGROUND)
    run("npm", "run", "build", cwd=PLAYGROUND)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update the YARA-X playground"
    )
    parser.add_argument(
        "version",
        type=parse_version,
        help="e.g. 1.22.0 or v1.22.0",
    )

    version = parser.parse_args().version

    verify_npm_release(version)

    with tempfile.TemporaryDirectory(
        prefix="yara-x-playground-"
    ) as temporary:
        directory = Path(temporary)

        source = fetch_release(version, directory)
        wasm = build_language_server(source)
        bindings = generate_bindings(source, wasm, directory)
        update_playground(version, bindings)

    print("\nPlayground updated. Review the diff before committing.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Update failed: {error}") from None
