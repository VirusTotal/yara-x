---
title: "Beware of the wildcard"
description: "Introducing the new unintended_pattern_in_set compiler warning in YARA-X to catch overlapping variable prefixes and pattern set collisions."
summary: ""
date: 2026-08-05T00:00:00+01:00
lastmod: 2026-08-05T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Victor M. Alvarez" ]
pinned: false
homepage: false
seo:
  title: "Beware of the wildcard"
  description: "Introducing the new unintended_pattern_in_set compiler warning in YARA-X to catch overlapping variable prefixes and pattern set collisions."
  canonical: ""
  noindex: false
---

When crafting YARA rules, wildcard pattern sets like `any of ($s*)` or 
`all of ($c*)` are a very convenient feature of the language. They allow
rule authors to group related strings under a common prefix, keeping
condition logic clean and maintainable.

However, while inspecting real-world YARA rules in search of optimization
opportunities, I realized that wildcard pattern sets are also one of the 
subtlest sources of silent logic bugs. Consider this YARA rule:

```yara
rule example_1 {
  strings:
    $b1 = "pluginWrapper plugin_"
    $b2 = "data-areaid="
    $b3 = "PowerbyDedeCms"
    $b4 = "dede_fieldshash"
    $b5 = "/plus/diy.php"
      
    $bd1 = "@eval($_POST["
    $bd2 = "@Assert($_POST["

  condition:
    2 of ($b*) and 1 of ($bd*)
}  
```

The intention of this rule seems clear: it should detect any file
containing two occurrences of the patterns `$b1` through `$b5`, and one
occurrence of either `$bd1` or `$bd2`. Right?

Well, that may be the intention, but it's not what the rule actually does.
Do you see why? Take another look.

The issue here is that `$b*` matches every pattern identifier starting
with `$b`—which includes `$b1` through `$b5`, but also `$bd1` and `$bd2`.
In practice, because of the `1 of ($bd*)` clause, the condition requires either
`$bd1` or `$bd2` to be present. If both `$bd1` and `$bd2` are present, they
themselves satisfy `2 of ($b*)`, meaning none of the strings `$b1` through `$b5`
are required at all! If only one of `$bd1` or `$bd2` is present, then only a
single occurrence from `$b1` through `$b5` is required—not two, as `2 of ($b*)`
seems to suggest. The matching occurrence of `$bd1` or `$bd2` counts toward
evaluating `2 of ($b*)`.

Perhaps the rule's author intended this exact behavior, but I doubt it.
Now take a look at another example where the error is even more obvious:

```yara
rule example_2 {
  strings:
    $this = "This program cannot be run"
    $t1 = "SAServer"
    $t2 = "Pass:"
    $t3 = "User:"
  
  condition:
    $this and 1 of ($t*)
}
```

The `$this` pattern is explicitly required, but because `$t*` also matches `$this`,
the `1 of ($t*)` clause is completely redundant. If `$this` is true, then `1 of ($t*)`
is automatically true as well, regardless of whether `$t1`, `$t2`, or `$t3` are found.

Issues like these turn out to be quite common in real-world rules, and I've found
multiple examples among the rules we have in VirusTotal. So I decided to implement
a new compiler warning to help detect this kind of error automatically. It proved
more challenging than I initially expected, but after a few iterations, I arrived
at a solution that works remarkably well.

Here is what the warning looks like in action:

```text
warning[unintended_pattern_in_set]: pattern `$this` may be unintendedly or redundantly included in pattern set `$t*`
 --> test.yar:9:5
  |
9 |     $this and 1 of ($t*)
  |     -----           --- `$this` is also included in `$t*`
  |     |
  |     `$this` is used here
```

This feature will be released in the upcoming YARA-X v1.20.0. Until then,
let me know what you think about it!