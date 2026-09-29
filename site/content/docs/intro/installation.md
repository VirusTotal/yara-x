---
title: "Installation"
description: "How to install YARA-X"
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "installation"
weight: 120
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

## Installing with pre-built binaries

The easiest way to install YARA-X is to download one of the pre-built binaries
distributed with each [release](https://github.com/VirusTotal/yara-x/releases).

Pre-built binaries are available for Linux, macOS, and Windows. Download the
appropriate archive, extract it to your preferred location, and you're ready to
run YARA-X.

## Installing from source

On macOS, you can also use `brew`:

```shell
brew install yara-x
```

For building YARA-X, you will need a recent version of Rust. Follow the
instructions in the
[Rust official site](https://www.rust-lang.org/learn/get-started).

Once Rust is installed on your system, run:

```bash
git clone https://github.com/VirusTotal/yara-x
cd yara-x
cargo install --path cli
```

## Building the documentation

To build the YARA-X documentation, you will need Node.js and either npm or pnpm
installed.

```bash
cd yara-x/site
pnpm install
pnpm run build
```

## Building Python package

To build the YARA-X Python package, create and activate a virtual environment:

```bash
pip install virtualenv
virtualenv venv
source venv/bin/activate
```

Install the build dependencies:

```bash
pip install maturin
```

Build the package with support for the `test_proto2` and `test_proto3` modules:

```bash
maturin build \
  --manifest-path py/Cargo.toml \
  --release \
  --features=test_proto2-module,test_proto3-module
```

Install the generated wheel:

```bash
pip install target/wheels/yara_x-*.whl
```
