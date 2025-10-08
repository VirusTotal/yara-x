---
title: "Smarter is not always better"
description: ""
summary: ""
date: 2025-09-12T00:00:00+01:00
lastmod: 2025-09-12T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Victor M. Alvarez" ]
pinned: false
homepage: false
seo:
  title: "Smarter is not always better"
  description: ""
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---


Anyone who has used YARA knows that performance matters. When you’re scanning
large datasets or malware samples, even small inefficiencies can add up. This
is why YARA-X introduced smarter heuristics for extracting atoms — fixed 
substrings derived from regular expressions that are used during the pattern 
search phase.

Most of the time, these improved heuristics make scanning much faster. But recently
I ran into an unusual case where they actually made things much slower, and it’s
a great example of how optimizations can sometimes backfire.

# A quick refresher: What are atoms?

When YARA processes a rule that includes a regular expression, it first tries to
extract one or more short atoms from it. Atoms are small fixed substrings (up to 
4 bytes long) that definitely appear in any string matching the regex. YARA uses
these atoms during the initial pattern search phase: it scans the input data 
looking only for those atoms.

Every time an atom is found, YARA then evaluates the full regex at that location
to confirm whether it’s an actual match. 

Choosing the right atoms is crucial, short or common atoms are likely to appear
everywhere, triggering lots of unnecessary regex evaluations. In the other hand,
longer or rarer atoms appear less often, reducing the number of evaluations and 
making scanning faster.

## How YARA-X improves on YARA

YARA-X improves on YARA by trying to maximize the length and uniqueness of the 
atoms it extracts. This is usually a big win for performance.

Consider this regex:

```
/[A-Za-z0-9+\/]{64,512}\x00/
```

Here’s what happens:

* The character set `[A-Za-z0-9+\/]` includes 64 possible characters (`A–Z`, `a–z`, `0–9`, `+`, `/`).
* The quantifier `{64,512}` means the regex expects at least 64 of those characters 
  in a row.
* YARA-X sees this and generates every possible two-character combination from those
  64 characters.
* 64 × 64 = 4096 possible two-byte atoms.

Meanwhile, YARA only extracts a single atom from the same regex — the trailing `\x00`. It
doesn’t even attempt to extract anything from the rest of the regex.

At first glance, this seems like a clear win for YARA-X: using `00` as an atom is a terrible
idea because it’s extremely common, while YARA-X’s longer atoms should be much rarer and faster
to search.

### When smarter backfires

Here’s where things get interesting.

The file 4b8a2a7f9b1c28ee28e28f017eb656a61bab506c66cee3e46a3e3af356446bc9 contains a very large
Base64 string near the end, and here’s how the two engines behave with this file:

* YARA finds 7024 occurrences of its single `00` atom → 7024 regex evaluations.
* YARA-X finds 815,359 occurrences of its 4096 two-byte atoms → 815,359 regex evaluations.

That’s a difference of two orders of magnitude! YARA ends up being much faster in this specific
case, simply because its sloppy atom extraction played in its favor.

This is a rare edge case, but it illustrates an important point: Although better heuristics
usually win, they can also backfire on edge cases. In certain pathological files, having more
and longer atoms can actually hurt performance if they happen to appear extremely frequently 
in the data.

Performance depends on content, not just size. A file full of repetitive Base64 data can be
harder to scan than a much larger file with diverse content.

In most real-world scenarios, YARA-X will do a better job with this rule. But this case 
shows that even “smarter” optimizations that work better most of the time, can be outsmarted 
by weird data — and that’s what makes performance engineering so interesting.