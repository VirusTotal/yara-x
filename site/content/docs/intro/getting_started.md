---
title: "Getting started"
description: "Guides lead a user through a specific task they want to accomplish, often with a sequence of steps."
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "getting_started"
weight: 110
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---


YARA-X is a re-incarnation of  [YARA](https://virustotal.github.io/yara), a
pattern matching tool designed with malware researchers in mind. This new
incarnation intends to be faster, safer and more user-friendly than its
predecessor. The ultimate goal of YARA-X is replacing YARA as the default
pattern matching tool for malware researchers.

With YARA-X you can create descriptions of malware families (or whatever you
want to describe) based on textual or binary patterns. Each description (a.k.a.
rule) consists of a set of patterns and a boolean expression which determine its
logic. Let's see an example:

```yara
rule silent_banker : banker {
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true

    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}
```

## Further reading

- If you are completely new to YARA, you should start by
  learning [how to write YARA rules]({{< ref "syntax.md" >}}).

- Seasoned YARA users may want to know about the
  [differences between YARA-X and YARA]({{< ref "differences.md" >}})