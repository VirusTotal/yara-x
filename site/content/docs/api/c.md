---
title: "C/C++"
description: ""
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "c-api"
weight: 510
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

C and C++ are still among the most popular languages for systems programming
and, the *lingua franca* for interoperability between languages. Without the
posibility of talking to C/C++ code, YARA-X would never get serious adoption.
For this reason, we provide a C API that allows interacting with YARA-X from
C/C++ programs.

This section describes the C API and explains how to create the header files
and libraries that you will need to integrate YARA-X in your project.

## Building the C library

The easiest way for building the C library is
using [`cargo-c`](https://github.com/lu-zero/cargo-c), if you
didn't install it before, this is the first step:

```shell
cargo install cargo-c
```

Once `cargo-c` in installed, go to the root directory of the YARA-X repository
and type:

```shell
cargo cinstall -p yara-x-capi --release
```

The command above will put the library and header files in the correct path
in your system (usually `/usr/local/lib` and `/usr/local/include` for Linux
and MacOS users), and will generate a `.pc` file so that `pkg-config` knows
about the library.

In Linux and MacOS you can check if everything went fine by compiling a simple
test program, like this:

```shell
cat <<EOF > test.c
#include <yara_x.h>
int main() {
    YRX_RULES* rules;
    yrx_compile("rule dummy { condition: true }", &rules);
    yrx_rules_destroy(rules);
}
EOF

gcc `pkg-config --cflags yara_x_capi` `pkg-config --libs yara_x_capi` test.c
```

The compilation should succeed without errors.

Windows users will find all the files needed for importing YARA-X in the
`target/x86_64-pc-windows-msvc/release` directory. This includes:

* A header file `yara_x.h`
* A [module definition file]() `yara_x_capi.def`
* A DLL file `yara_x_capi.dll` with its corresponding import
  library `yara_x_capi.dll.lib`
* A static library `yara_x_capi.lib`


