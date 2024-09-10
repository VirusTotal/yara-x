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

The most straightforward way of installing YARA-X in your system is downloading
one of the pre-built binaries that we distribute with
every [release](https://github.com/VirusTotal/yara-x/releases). You will find
pre-built binaries for Linux, macOS, and Windows, unzip the binary in
your preferred location, and that's all, you are ready to run YARA-X.

In macOS, you can also use `brew`:

```shell
brew install yara-x
```

If you prefer to build YARA-X yourself, follow the guide below.

## Installing with cargo

For building YARA-X you will need a recent version of Rust. Follow the
instructions in
the [Rust official site](https://www.rust-lang.org/learn/get-started).

Once you have Rust installed in your system, type:

```bash
git clone https://github.com/VirusTotal/yara-x 
cd yara-x
cargo install --path cli
```
