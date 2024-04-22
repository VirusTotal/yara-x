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
pre-built x86_64 binaries for Linux, macOS, and Windows, unzip the binary in
your preferred location, and voilá, you are ready to run YARA-X.

If you prefer to build YARA-X yourself, follow the guide below.

## Pre-requisites

For building YARA-X you will need:

* A recent version of `rustc` (version 1.7.4 or newer) and `cargo`. Follow
  the
  instructions in
  the [Rust official site](https://www.rust-lang.org/learn/get-started).
* The `openssl` library and its header files.

{{< tabs "install-openssl" >}}
{{< tab "Linux" >}}

```bash
sudo apt install libssl-dev
```

{{< /tab >}}
{{< tab "macOS" >}}

```bash
brew install openssl@3
```

{{< /tab >}}
{{< tab "Windows" >}}

```bash
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg && bootstrap-vcpkg.bat
vcpkg install openssl
```

{{< /tab >}}
{{< /tabs >}}

## Installing with cargo

```bash
git clone https://github.com/VirusTotal/yara-x 
cd yara-x
cargo install --path cli
```
