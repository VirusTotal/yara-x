---
title: "Hex patterns"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "hex_patterns"
weight: 230
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Hex patterns allow to search for arbitrary byte sequences. They allow four
special constructions that make them more flexible: wildcards, negations, jumps,
and alternatives.

## Wildcards

Wildcards are simply placeholders that you can put in the pattern indicating
that some bytes are unknown, and they should match anything. The placeholder
character is the question mark (`?`). Here you have an example of a hex pattern
with wildcards:

```yara
rule WildcardExample {
    strings:
        $hex = { E2 34 ?? C8 A? FB }
    condition:
        $hex
}
```

As shown in the example the wildcards are nibble-wise, which means that you can
define just one nibble of the byte and leave the other unknown (e.g: `A?`).

## Negation

You may also specify that a byte is not a specific value. For that you can use
the `not` operator:

```yara
rule NotExample {
    strings:
        $hex_1 = { F4 23 ~00 62 B4 }
        $hex_2 = { F4 23 ~?0 62 B4 }
    condition:
        $hex_1 and $hex_2
}
```

In the example above we have a byte prefixed with a tilde (`~`), which is the
not operator. This defines that the byte in that location can take any value
except the value specified. In this case the first string will only match if the
byte is not `00`. The not operator can also be used with nibble-wise wildcards,
so the second string will only match if the second nibble is not zero.

## Jumps

Wildcards and `not` operators are useful when defining patterns whose content
can vary, but you know the length of the variable chunks, however, this is not
always the case. In some circumstances you may need to define patterns with
chunks of variable content and length. In those situations you can use jumps
instead of wildcards:

```yara
rule JumpExample {
    strings:
        $hex = { F4 23 [4-6] 62 B4 }
    condition:
        $hex
}
```

In the example above we have a pair of numbers enclosed in square brackets and
separated by a hyphen, that's a jump. This jump is indicating that any arbitrary
sequence from 4 to 6 bytes can occupy the position of the jump. Any of the
following strings will match the pattern:

```
F4 23 01 02 03 04 62 B4
```

```
F4 23 00 00 00 00 00 62 B4
```

```
F4 23 15 82 A3 04 45 22 62 B4
```

Any jump `[X-Y]` must meet the condition 0 <= X <= Y. These are valid jumps:

```
FE 39 45 [0-8] 89 00
```

```
FE 39 45 [23-45] 89 00
```

```
FE 39 45 [1000-2000] 89 00
```

But this is invalid, because the lower bound is greater than the lower bound:

```
FE 39 45 [10-7] 89 00
```

If the lower and higher bounds are equal you can write a single number enclosed
in brackets, like this:

```
FE 39 45 [6] 89 00
```

The above string is equivalent to both of these:

```
FE 39 45 [6-6] 89 00
```

```
FE 39 45 ?? ?? ?? ?? ?? ?? 89 00
```

The bounds can be also implicit:

```
FE 39 45 [10-] 89 00
```

```
FE 39 45 [-] 89 00
```

The first one means `[10-infinite]`, the second one means `[0-infinite]`.

## Alternatives

There are also situations in which you may want to provide different
alternatives for a given fragment of your hex pattern. In those situations you
can use a syntax which resembles a regular expression:

```yara
rule AlternativesExample1 {
    strings:
        $hex = { F4 23 ( 62 B4 | 56 ) 45 }
    condition:
        $hex
}
```

This rule will match any file containing `F4 23 62 B4 45` or `F4 23 56 45`.

But more than two alternatives can be also expressed. In fact, there are no
limits to the amount of alternative sequences you can provide, and neither to
their lengths.

```yara
rule AlternativesExample2 {
    strings:
        $hex = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }
    condition:
        $hex
}
```

As can be seen also in the above example, patterns containing wildcards are
allowed as part of alternative sequences.