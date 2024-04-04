---
title: "Text patterns"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "text_patterns"
weight: 220
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Text patterns are the most common type of patterns in YARA rules. They are
plain text strings, like in the following example:

```yara
rule TextExample{
    strings:
        $text = "foobar"
    condition:
        $text
}
```

This is the simplest case: an ASCII-encoded, case-sensitive string. However,
text patterns can have modifiers that alter the way in which the pattern will
be interpreted. Those modifiers are appended at the end of the pattern
definition, as discussed below.

## "nocase" modifier

Text patterns in YARA are case-sensitive by default, but you can turn your
pattern into a case-insensitive one by appending the `nocase` modifier at the
end of the pattern definition:

```yara
rule CaseInsensitiveTextExample {
    strings:
        $text = "foobar" nocase
    condition:
        $text
}
```

With the `nocase` modifier the pattern "foobar" will match "Foobar", "FOOBAR",
and "fOoBaR". This modifier can be used in conjunction with any modifier, except
`base64`, `base64wide` and `xor`.

## "wide" modifier

The `wide` modifier can be used to search for strings encoded with two bytes per
character, something typical in many executable binaries.

For example, if the string "Borland" appears encoded as two bytes per
character (i.e. `B\x00o\x00r\x00l\x00a\x00n\x00d\x00`), then the following rule
will match:

```yara
rule WideCharTextExample1 {
    strings:
        $wide = "Borland" wide
    condition:
        $wide
}
```

However, keep in mind that this modifier just interleaves the ASCII codes of the
characters in the string with zeroes, it does not support truly UTF-16 strings
containing non-English characters. If you want to search for strings in both
ASCII and wide form, you can use the `ascii` modifier in conjunction
with `wide`, no matter the order in which they appear.

```yara
rule WideCharTextExample2 {
    strings:
        $wide_and_ascii = "Borland" wide ascii
    condition:
        $wide_and_ascii
}
```

The `ascii` modifier can appear alone, without an accompanying `wide` modifier,
but it's not necessary to write it because in absence of `wide` the string is
assumed to be ASCII by default.

## "xor" modifier

The `xor` modifier can be used to search for strings that are XORed with a
single byte.

The following rule will search for every single byte XOR applied to the string "
This program cannot" (including the plaintext string):

```yara
rule XorExample1 {
    strings:
        $xor = "This program cannot" xor
    condition:
        $xor
}
```

The above rule is logically equivalent to:

```yara
rule XorExample2 {
    strings:
        $xor_00 = "This program cannot"
        $xor_01 = "Uihr!qsnfs`l!b`oonu"
        $xor_02 = "Vjkq\"rpmepco\"acllmv"
        // Repeat for every single byte XOR
    condition:
        any of them
}
```

You can also combine the `xor` modifier with `wide` and `ascii` modifiers. For
example, to search for the `wide` and `ascii` versions of a string after every
single byte XOR has been applied you would use:

```yara
rule XorExample3 {
    strings:
        $xor = "This program cannot" xor wide ascii
    condition:
        $xor
}
```

The `xor` modifier is applied after the `wide` modifier. This means that using
the `xor` and `wide` together results in the XOR applying to the interleaved
zero bytes. For example, the following two rules are logically equivalent:

```yara
rule XorExample4 {
    strings:
        $xor = "This program cannot" xor wide
    condition:
        $xor
}
```

```yara
rule XorExample4 {
    strings:
        $xor_00 = "T\x00h\x00i\x00s\x00 \x00p\x00r\x00o\x00g\x00r\x00a\x00m\x00\x00c\x00a\x00n\x00n\x00o\x00t\x00"
        $xor_01 = "U\x01i\x01h\x01r\x01!\x01q\x01s\x01n\x01f\x01s\x01`\x01l\x01!\x01b\x01`\x01o\x01o\x01n\x01u\x01"
        $xor_02 = "V\x02j\x02k\x02q\x02\"\x02r\x02p\x02m\x02e\x02p\x02c\x02o\x02\"\x02a\x02c\x02l\x02l\x02m\x02v\x02"
        // Repeat for every single byte XOR operation.
    condition:
        any of them
}
```

If you want more control over the range of bytes used with the `xor` modifier
use:

```yara
rule XorExample5 {
    strings:
        $xor = "This program cannot" xor(0x01-0xff)
    condition:
        $xor
}
```

The above example will apply the bytes from 0x01 to 0xff, inclusively, to the
string when searching. The general syntax is xor(minimum-maximum).

## "fullword" modifier

Another modifier that can be applied to text patterns is `fullword`. This
modifier guarantees that the pattern will match only if it appears in the file
delimited by non-alphanumeric characters. For instance, the string "domain", if
defined as `fullword`, doesn't match "www.mydomain.com" but it
matches "www.my-domain.com" and "www.domain.com".

## "base64" modifier

The `base64` modifier can be used to search for strings that have been base64
encoded. A good explanation of the technique is at:

https://www.leeholmes.com/searching-for-content-in-base-64-strings/

The following rule will search for the three base64 permutations of the string
"This program cannot":

```yara
rule Base64Example1 {
    strings:
        $a = "This program cannot" base64
    condition:
        $a
}
```

This will cause YARA to search for these three permutations:

```
VGhpcyBwcm9ncmFtIGNhbm5vd
RoaXMgcHJvZ3JhbSBjYW5ub3
UaGlzIHByb2dyYW0gY2Fubm90
```

The `base64wide` modifier works just like the `base64` modifier but the results
of the `base64` modifier are converted to wide.

The interaction between `base64` (or `base64wide`) and `wide` and `ascii` is as
you might expect. `wide` and `ascii` are applied to the string first, and then
the `base64` and `base64wide` modifiers are applied. At no point is the
plaintext of the `ascii` or `wide` versions of the strings included in the
search. If you want to also include those you can put them in a secondary
pattern.

The `base64` and `base64wide` modifiers also support a custom alphabet. For
example:

```yara
rule Base64Example2 {
    strings:
        $a = "This program cannot" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
    condition:
        $a
}
```

The alphabet must be 64 bytes long.

The `base64` and `base64wide` modifiers are only supported for text patterns
that are at least 3 bytes long. Using these modifiers with a hex patterns,
regular expression, or text patterns that are too short, will cause a compiler
error. Also, the `xor`, `fullword`, and `nocase` modifiers used in combination
with `base64` or `base64wide` will cause a compiler error.

{{< callout title="Incompatibility notice">}}

In YARA 4.x the `base64` and `base64wide` modifiers can produce false positives.
For instance, the pattern `"This program cannot" base64` can match both
"Dhis program cannow" and "This program cannot". This issue has been solved
in YARA-X, but the drawback is that patterns shorter than 3 characters are
don't accept these modifiers.

{{< /callout >}}

