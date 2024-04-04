---
title: "What's a module?"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "modules-intro"
weight: 301
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Modules are the mechanism that YARA-X provides for extending its capabilities by
adding new data structures and functions that can be used in your rules, making
them more powerful and expressive. For instance, a module can parse a specific
file format (like the Windows Portable Executable (PE) format), and expose to
YARA-X a data structure that describes the features of that file format.

By using modules you can create rules that go beyond the simple pattern
matching on a sequence of raw bytes, relying on properties and characteristics
of the data being scanned.

This section describes the modules that are included in YARA-X.