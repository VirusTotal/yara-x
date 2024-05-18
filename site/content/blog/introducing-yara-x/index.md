---
title: "YARA is dead, long live YARA-X"
description: ""
summary: ""
date: 2024-05-17T00:00:00+01:00
lastmod: 2024-05-17T00:00:00+01:00
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

For over 15 years, [YARA](https://github.com/VirusTotal/yara) has been growing
and evolving until it became an indispensable tool in every malware researcher's
toolbox. Throughout this time YARA has seen numerous updates, with new features
added and countless bugs fixed. But today, I'm excited to announce the biggest
change yet: a full rewrite.

YARA-X is a completely new implementation of YARA in Rust, and it has the
following goals:

* **Better user experience**: The new command-line interface is more modern and
  colorful, and error reports are now more explicative. More features aimed at
  improving the user's experience will be incorporated in the future.

* **Rule-level compatibility**: While achieving 100% compatibility is tough, our
  aim is to make YARA-X 99% compatible with YARA at the rule level.
  Incompatibilities should be minimal and thoroughly documented.

* **Improved performance**: YARA is known for its speed, but certain rules,
  especially those utilizing regular expressions or complex loops, can slow it
  down. YARA-X excels with these rules, often delivering significantly faster
  results. Our ultimate goal is for YARA-X to outperform YARA across the board.

* **Enhanced reliability and security**: YARA's complexity in C code can lead to
  bugs and security vulnerabilities. YARA-X is built with Rust, offering greater
  reliability and security.

* **Developer-friendly**: We're prioritizing ease of integration into other
  projects and simplified maintenance. Official APIs for Python, Golang, and C
  are provided to facilitate seamless integration. YARA-X also addresses
  some of the design flaws that made YARA challenging to maintain and extend.

## Why a rewrite?

Was a complete rewrite necessary to achieve such goals? This question lingered
in my mind for a long time before deciding to rewrite YARA. Rewriting is
risky, it introduces new bugs, backward compatibility issues, and doubles the
maintenance efforts, since legacy code doesn't disappear after launching the new
system. In fact, the legacy system may be still in use for years, if not
decades.

However, I believe a rewrite was the right decision for multiple reasons:

* YARA is not a large project, it's a medium-size project that lacks subsystems
  or components large enough to be migrated in isolation. Incremental migration
  to Rust was impractical because large portions of the code are interconnected.

* The improvements I envisioned required significant design changes.
  Implementing these in the existing C codebase would involve extensive
  rewrites, carrying the same risks as starting fresh with Rust.

* After a year of working on the project, I’ve found Rust easier to maintain
  than C. Rust offers stronger reliability guarantees and simplifies integrating
  third-party code, especially for multi-platform projects.

## Is YARA really dead?

Despite the dramatic title of this post, YARA is not actually dead. I’m aware
that many people and organizations rely on YARA to get important work done, and
I don’t want to let them down.

YARA is still being maintained, and future releases will include bug fixes and
minor features. However, don’t expect new large features or modules. All efforts
to enhance YARA, including the addition of new modules, will now focus on
YARA-X.

## What's the current state of YARA-X?

YARA-X is still in beta, but is mature and stable enough for use, specially
from the command-line interface or one-shot Python scripts. While the APIs may
still undergo minor changes, the foundational aspects are already established.

At VirusTotal, we have been running YARA-X alongside YARA for a while, scanning
millions of files with tens of thousands of rules, and addressing discrepancies
between the two. This means that YARA-X is already battle-tested. These tests
have even uncovered YARA bugs!

Please test YARA-X and don't hesitate
to [open an issue](https://github.com/VirusTotal/yara-x/issues/new) if you find
a bug or some feature that you want to see implemented.

## What's next?

My aim is to surpass YARA in every possible aspect with YARA-X. I want it to be
so superior that existing YARA users willingly migrate to YARA-X for its
undeniable advantages, not because they are forced to do so.

Publishing a beta version is only the first step towards this goal. I'll
continue to enhance YARA-X, releasing updates and sharing insights through blog
posts like this one.

Stay tuned, because this journey has only just begun.