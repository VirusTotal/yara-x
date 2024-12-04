---
title: "VirusTotal moves to YARA-X"
description: ""
summary: ""
date: 2024-12-04T00:00:00+01:00
lastmod: 2024-12-04T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Victor M. Alvarez" ]
pinned: false
homepage: false
seo:
  title: "VirusTotal moves to YARA-X" # custom title (optional)
  description: "Announces that VirusTotal is now using YARA-X for Livehunt and Retrohunt" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

When I began developing YARA-X, my primary goal was to create a tool capable of
eventually replacing YARA for serious, professional use. While YARA-X is still
under active development, it has been stable and mature for several months. It
was ready to reach an important milestone: fully replace YARA in the VirusTotal
services, namely: [Livehunt](https://docs.virustotal.com/docs/livehunt)
and [Retrohunt](https://docs.virustotal.com/docs/retrohunt).

We’re thrilled to announce that YARA-X is now the engine powering both services.

## What changes for our users?

#### New modules: macho and lnk

Users can now take advantage of two new YARA modules available in Livehunt and
Retrohunt:

* `macho` module: Similar to the popular `pe` module, but tailored for macOS
  Mach-O executable files.

* `lnk` module: Exposes metadata contained
  in [Windows Link Files (LNK)](https://forensics.wiki/lnk/),
  which
  have [been used by threat actors](https://intezer.com/blog/malware-analysis/how-threat-actors-abuse-lnk-files/)
  in numerous campaings.

These additions, which were contributions from our community, provide malware
researchers with powerful new tools. Thanks
to [Tomáš Ďuriš](https://github.com/TommYDeeee)
and [Jacob Latonis](https://github.com/latonis) for their work on the `macho`
module, and
[BitsOfBinary](https://github.com/BitsOfBinary]) for the original implementation
of the `lnk` module in YARA)

Learn more about them in [macho documentation](/docs/modules/macho) and
[lnk documentation](/docs/modules/lnk).

#### More rules accepted

The second thing that changes is that some YARA rules that were not accepted in
the past will be accepted now. Regular users of Livehunt and Retrohunt probably
know what I'm talking about. In order to guarantee the stability of these
services, we had to adopt the policy of not allowing YARA rules that generate
performance warnings, which resulted in the infamous: _"string $foo may
slowdown scanning"_ error. Without this policy, a single inefficient YARA rule
could cause a huge impact and affect the service for all our users. This policy
is still in place, but as YARA-X produces less of these warnings, many YARA
rules that were rejected in the past will be accepted now.

#### Fewer timeouts

Lastly, we’ve made significant strides in reducing timeouts—a challenge users
might not always notice but one that impacts everyone. Inefficient rules that
take too long to scan a file are interrupted after a timeout period, currently
set to 90 seconds.

Timeouts can lead to missed matches for the rule’s creator and block other
users’ rules from scanning the same file. Before migrating to YARA-X, timeouts
affected roughly 2% of scanned files. With YARA-X, this number has dropped to
under 0.2%.
