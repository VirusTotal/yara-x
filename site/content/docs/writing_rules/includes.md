---
title: "Including files"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "includes"
weight: 290
toc: true
seo:
  title: "Including files"
  description: "Explains how to use the YARA `include` directive"
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

To better organize your YARA rule files, you can use the `include` directive.
This directive functions similarly to the `#include` preprocessor directive in
C/C++, inserting the contents of the specified file into the current file at
compile time. For example, the following line includes the contents of
`other.yar` into the current source file:

```
include "other.yar"
```

You can also use relative paths, like in the following examples:

```
include "includes/other.yar"
```

```
include "../includes/other.yar"
```

When resolving included files, YARA-X searches the directories specified with
the `--include-dir` (or `-I`) option. These directories are checked in the order
they were provided. If no include directories are specified, YARA-X will look
for the included files in the current working directory.