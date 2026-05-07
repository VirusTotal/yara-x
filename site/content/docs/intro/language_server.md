---
title: "Language Server"
description: "How to use the YARA-X Language Server"
summary: "YARA-X includes a Language Server that provides intelligent features to your code editor."
date: 2026-05-07T13:20:00+02:00
lastmod: 2026-05-07T13:20:00+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "language_server"
weight: 125
toc: true
---

YARA-X includes a Language Server that implements the Language Server Protocol
(LSP). This provides editor-agnostic features such as:

*   **Real-time diagnostics**: Instant feedback on syntax errors as you type.
*   **Advanced autocompletion**: Suggestions for module identifiers and keywords.
*   **Go to definition**: Quick navigation to rule or pattern definitions.
*   **Automatic formatting**: Keeps your rules clean and consistent.

An extension for Visual Studio Code is available in the [Visual Studio
Marketplace](https://marketplace.visualstudio.com/items?itemName=virustotal.yara-x-ls).
For more details, see the [Introducing the YARA language server]({{< ref
"blog/introducing-language-server/index.md" >}}) blog post.
