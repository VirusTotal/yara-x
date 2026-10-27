---
title: "magic"
description: ""
summary: ""
date: 2026-10-27T12:00:00+00:00
lastmod: 2026-10-27T12:00:00+00:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "magic-module"
weight: 650
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `magic` module uses [libmagic](https://man7.org/linux/man-pages/man3/libmagic.3.html),
the library behind the Unix `file` command, to identify the type of the data
being scanned. This lets you write rules that depend on what kind of file is
being scanned, instead of on specific bytes inside it.

{{< callout context="caution" title="Important">}}

The `magic` module is disabled by default. To use it, YARA-X must be built with
the `magic-module` feature of the `yara-x` crate, on a system where libmagic and
its database are installed. The `yara-x-py`, `yara-x-capi` and `yara-x-ls`
crates have their own `magic-module` feature that turns it on.

{{< /callout >}}

-------

## Functions

### type()

Returns a string that describes the type of the data being scanned, the same
description that the Unix `file` command prints. Returns undefined if libmagic
fails to analyze the data.

The exact wording depends on the version of libmagic and on its database, so
prefer `contains` or `startswith` over `==` unless you control the environment
where the rule runs.

Examples:

`magic.type() contains "PDF document"`

`magic.type() startswith "ELF"`

### mime_type()

Returns the [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types)
of the data being scanned, as reported by libmagic. Returns undefined if libmagic
fails to analyze the data.

Examples:

`magic.mime_type() == "application/pdf"`

`magic.mime_type() == "text/plain"`

{{< callout context="note" title="Note">}}

Both functions analyze the data once per scanned file and reuse the result, so
using them several times in the same rule, or in several rules, is cheap.

{{< /callout >}}

#### Examples

The output of libmagic for a few common files:

| File           | `magic.type()`                                     | `magic.mime_type()`  |
|----------------|----------------------------------------------------|----------------------|
| A PDF document | `PDF document, version 1.4`                        | `application/pdf`    |
| A PNG image    | `PNG image data, 1 x 1, 8-bit/color RGBA, ...`     | `image/png`          |
| A ZIP archive  | `Zip archive data, at least v2.0 to extract, ...`  | `application/zip`    |
| A Bash script  | `Bourne-Again shell script, ASCII text executable` | `text/x-shellscript` |

These values come from libmagic 5.45 and may differ in other versions.

```
import "magic"

rule PdfDocument {
    condition:
        magic.mime_type() == "application/pdf"
}

rule ShellScript {
    condition:
        magic.type() contains "shell script"
}

rule SmallArchive {
    condition:
        magic.mime_type() == "application/zip" and filesize < 1MB
}
```
