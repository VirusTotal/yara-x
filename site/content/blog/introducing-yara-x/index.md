---
title: "YARA is dead, long live YARA-X"
description: ""
summary: ""
date: 2024-03-26T15:10:26+01:00
lastmod: 2024-03-26T15:10:26+01:00
draft: true
weight: 50
categories: [ ]
tags: [ ]
contributors: [ ]
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
  aim is to make YARA-X 99% compatible with YARA at the rule level. Any
  incompatibilities will be minimal and thoroughly documented.

* **Improved performance**: YARA is known for its speed, but certain rules,
  especially those utilizing regular expressions or complex loops, can slow it
  down. YARA-X excels with these rules, often delivering significantly faster
  results. Our ultimate goal is for YARA-X to outperform YARA across the board.

* **Enhanced reliability and security**: YARA's complexity in C code can lead to
  bugs and security vulnerabilities. YARA-X is built with Rust, offering greater
  reliability and security.

* **Developer-friendly**: We're prioritizing ease of integration into other
  projects and simplified maintenance. Official APIs for Python, Golang, and C
  will be provided to facilitate seamless integration. YARA-X also addresses
  some of the design flaws that made YARA challenging to maintain and extend.

## But why a rewrite?

It was really necessary a complete rewrite in order to achieve such goals?

## Is YARA really dead?

In despite of the dramatic title of this post, YARA is not actually dead. I'm
aware of the many people and organizations that are currently using YARA for
getting important stuff done, and I don't want to let these people down.

YARA is still being maintained, and new releases will be published in the
future, but they will contain only bug fixes and minor features. Don't expect
new large features or modules being added to YARA. All the efforts for making
YARA a better tool, including the addition of new modules, will go to YARA-X.
