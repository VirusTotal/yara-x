---
title: "Undefined values"
description: "Explains what are undefined values in YARA"
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "undefined"
weight: 280
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Modules often leave variables in an undefined state, for example when the
variable doesn't make sense in the current context (think of `pe.entry_point`
while scanning a non-PE file). YARA handles undefined values in a way that
allows the rule to keep its meaningfulness. Take a look at this rule:

```yara
import "pe"

rule Test {
    strings:
        $a = "some string"
    condition:
        $a and pe.entry_point == 0x1000
}
```

If the scanned file isn't a PE file, this rule won't match even if "some string"
is present because both conditions (the string's presence and the correct entry
point) must be met. However, consider the `or` case:

```
$a or pe.entry_point == 0x1000
```

You would expect the rule to match if the file contains the string, even if it
isn't a PE file. That's exactly how YARA behaves. The logic is as follows:

If the expression in the condition is `undefined`, it would be translated
to `false` and the rule won't match.

Boolean operators `and` and `or` will treat `undefined` operands as `false`,
Which means that:

* `undefined` and `true` is `false`
* `undefined` and `false` is `false`
* `undefined` or `true` is `true`
* `undefined` or `false` is `false`

All the remaining operators, including the `not` operator, return `undefined` if
any of their operands is `undefined`.

In the expression above, `pe.entry_point == 0x1000` will be undefined for non-PE
files, because `pe.entry_point` is undefined for those files. This implies that
`$a or pe.entry_point == 0x1000` will be `true` if and only if `$a` is `true`.

If the condition was `pe.entry_point == 0x1000` alone, it evaluates to `false`
for non-PE files, and so will do `pe.entry_point != 0x1000` and `not
pe.entry_point == 0x1000`, as none of these expressions make sense for non-PE
files.

To check if some expression is defined use unary operator `defined`. Example:

`defined pe.entry_point`