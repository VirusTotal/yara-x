---
title: "Differences with YARA"
description: "Documents the differences between YARA-X and YARA."
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "differences"
weight: 310
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

One of the main goals of YARA-X is maintaining compatibility with YARA at
the rule level as much as possible. Most of your YARA rules will work with
YARA-X without changes, however, some differences are inevitable.

Our guiding principles are:

* Incompatibilities are a nuisance for our users and should be minimized.
* When some incompatibility exists it should be either a small one (i.e:
  unlikely to happen in real-life rules), or it should be for a good reason.

This document covers the differences between YARA-X and YARA. They are ordered
by importance, with the most important differences first.

## Stricter escaped characters in regular expressions

YARA 4.x accepts invalid escaped characters in regular expressions, and simply
treat them as the character itself. For instance, in `/foo\gbar/` the `\g`
sequence is not a valid escaped character and YARA translates `\g` into `g`,
so `/foo\gbar/` is equivalent to `/foogbar/`.

This has proven to be problematic, because it's rarely the desired behaviour
and often hides errors in the regular expression. For example, these are
real-life patterns where the relaxed policy around escaped characters is
backfiring:

```
/\\x64\Release\\create.pdb/
```

In the pattern above notice the `\R` in `\Release`. The intention was obviously
to match `\\x64\\Release\\create.pdb/`, but the missing \ goes unnoticed and
the resulting regular expression is `/\\x64Release\\create.pdb/`, which is
incorrect. Some other examples are:

```
/%TEMP%\NewGame/
```

```
/(debug|release)\eda2.pdb/
```

```
/\\AppData\\Roaming\\[0-9]{9,12}\VMwareCplLauncher\.exe/
```

```
/[a-z,A-Z]:\\SAM\\clients\\Sam3\\enc\\SAM\obj\\Release\\samsam\.pdb/
```

YARA 4.4 introduced the `--strict-escape` argument that turns on a strict
check on escaped characters and return an error in such cases. This is also
the default behaviour in YARA-X.

## Differences in base64 patterns

In YARA 4.x you can use the `base64` modifier with strings shorter than 3
characters, but YARA-X requires at least 3 characters. In the other hand, YARA-X
won't produce false positives with `base64` patterns as YARA does. This is a
well-known YARA 4.x issue described in
the documentation:

> Because of the way that YARA strips the leading and trailing characters after
> base64 encoding, one of the base64 encodings of "Dhis program cannow" and "
> This
> program cannot" are identical.

YARA-X doesn't suffer from these false positives, but the price to pay is that
patterns must be at least 3 characters long.

## Alphabets for base64 modifiers

In YARA 4.x if you use both `base64` and `base64wide` in the same string they
must use the same alphabet. If you specify a custom alphabet for `base64`, you
must do the same for `base64wide`, this is an error:

```
$a = "foo" base64 base64wide("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
```

In YARA-X you can specify different alphabets for `base64` and `base64wide`
in the same pattern. In the example above, `base64` will use the default
alphabet as always, while `base64wide` will use the custom alphabet.

## Global rules can't depend on non-global rules

In YARA 4.x a global rule can depend on a non-global rule, as long as the
non-global rule is declared first. For instance, this is valid in YARA 4.x:

```
rule my_non_global_rule {
  condition:
    ....
}

global rule my_global_rule {
  condition:
    my_non_global_rule
}
```

In YARA-X this is forbidden, global rules can only depend on other global rules.

## "of" statement accepts tuples of boolean expressions

In YARA 4.x the `of` statement accepts a tuple of pattern or rule identifiers.
In both cases the identifiers can contain wildcards. For example, both of these
are valid:

```
1 of ($a, $c, $b*, $*)
```

```
1 of (some_rule, another_rule*)
```

In YARA-X the first case remains the same, but the second one has been
generalized to accept arbitrary boolean expressions, like in...

```
1 of (true, false)
```

```
1 of ($a and not $b, $c, false)
```

Notice however that we have lost the possibility of using wildcards with rule
names. So, this is valid...

```
1 of (some_rule)
```

But this is not valid...

```
1 of (some_rule*)
```

## Using xor and fullword together

In YARA 4.x the combination `xor` and `fullword` looks for the bytes before
and after the XORed pattern and makes sure that they are not alphanumeric, so
the pattern `"mississippi" xor(1) fullword` matches `{lhrrhrrhqqh}`, which is
the
result of XORing `mississippi` with 1. The pattern matches because the XORed
`mississippi` is delimited by the non-alphanumeric characters `{` and `}`.

In YARA-X the bytes before and after the pattern are also XORed before checking
if they are alphanumeric, therefore `{lhrrhrrhqqh}` becomes `zmississippiz`,
which doesn't match `"mississippi" xor(1) fullword`. In other words, YARA-X
searches for full words contained inside a longer XORed string, which is
the intended behavior in most cases.

## Negative numbers as array indexes

The expression `@a[-1]` is valid in YARA 4.x, but its value is always
`undefined`. In YARA-X this is an error.

## Jump bounds in hex patterns

In YARA 4.x the following hex pattern is invalid:

`{ 01 02 03 [0x00-0x100] 04 05 06 }`

This is because the jump's upper and lower bounds can be expressed in base 10
only, `0x00` and `0x100` are not valid bounds. In YARA-X hex and octal values
are accepted.

## Duplicate rule modifiers

In YARA 4.x rules can have any number of `global` or `private` modifiers, for
instance, the following is valid:

```
global global global rule duplicated_global  {
   ... 
}
```

In YARA-X you can specify each modifier once. They can still appear in any
order, though. This very unlikely to affect any real-life rule.