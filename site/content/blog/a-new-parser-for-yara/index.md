---
title: "An new parser for YARA"
description: ""
summary: ""
date: 2024-07-31T00:00:00+01:00
lastmod: 2024-07-31T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Victor M. Alvarez" ]
pinned: false
homepage: false
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

One of the design goals for YARA-X was to create a parser that could be reused
in various tools like code formatters, linters, automatic rule generators. In
YARA, the parser is so tightly coupled with the code generator that it cannot
be repurposed. This forced developers to write their own parser for YARA rules,
leading to many unofficial parsers that often fell behind the official version.

From the outset, YARA-X aimed to address this by providing a reusable parser
that produced both an Abstract Syntax Tree (AST), and a Concrete Syntax Tree
(CST), also known as a lossless syntax tree. The CST retains all source code
details, like comments, newlines, and spacing, which are crucial for tools like
code formatters. This parser was initially based in the
excellent [Pest](https://pest.rs/) library.

However, starting with version 0.6.0, we decided to replace Pest with our own
custom-made parser. The reasons are twofold: first, the Pest parser is not
error-tolerant and aborts parsing at the first syntax error; second, the
produced CST is not modifiable, making it impractical for use cases like
automated code refactoring.

This issue was highlighted by [Tomáš Ďuriš](https://github.com/TommYDeeee)
and [Marek Milkovič](https://github.com/metthal) from Gen Digital. At Gen
Digital they are heavy users of YARA and were excited about the YARA-X project.
They contacted me early on, offering their help and many interesting ideas. One
of areas in which they wanted to contribute was in creating a Language Server
for Visual Studio Code.

A Visual Studio Code Language Server implements the Language Server Protocol
(LSP), which allows for features such as code completion, error checking,
navigation, and refactoring. It enhances the coding experience by providing
real-time feedback and intelligent code editing features. However, while the
Pest-based parser was an improvement over the legacy YARA parser, it was still
insufficient for implementing an LSP.

With the help of Tomáš Ďuriš, who conducted the initial research and
prototyping, I embarked on a major refactoring effort. This resulted in the
complete removal of the Pest-based parser and the creation of a new parser that
addresses all the previously mentioned shortcomings.

The new parser is error-resilient, and in the future it will be capable of
producing a modifiable CST. Additionally, it is faster for certain rules that
were pathologically bad cases for the Pest-based parser. For instance, this
seemingly simple YARA rule fails to compile with YARA-X 0.5.0 but works
perfectly with version 0.6.0.

```yara
rule bad { condition: ((((((((((( true ))))))))))) }
```

With these changes, the groundwork has been laid for developing more advanced
and powerful tools that can leverage the improved parsing capabilities.
