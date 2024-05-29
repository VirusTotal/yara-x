---
title: "Regular expressions"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "regular_expressions"
weight: 240
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Regular expressions are one of the most powerful features of YARA. They are
defined in the same way as text patterns, but enclosed in forward slashes
instead of double-quotes, like in the Perl programming language.

```yara
rule RegExpExample1 {
    strings:
        $re1 = /md5: [0-9a-fA-F]{32}/
        $re2 = /state: (on|off)/
    condition:
        $re1 and $re2
}
```

Regular expressions can be also followed by `nocase`, `ascii`, `wide`,
and `fullword` modifiers just like text patterns. The semantics of these
modifiers are the same in both cases.

Additionally, they can be followed by the characters `i` and `s` just after the
closing slash, which is a very common convention for specifying that the regular
expression is case-insensitive and that the dot (`.`) can match new-line
characters. For example:

```yara
rule RegExpExample2 {
    strings:
        $re1 = /foo/i    // This regexp is case-insensitive
        $re2 = /bar./s   // In this regexp the dot matches everything, including new-line
        $re3 = /baz./is  // Both modifiers can be used together
    condition:
        any of them
}
```

Notice that `/foo/i` is equivalent to `/foo/ nocase`, but we recommend the
latter when defining strings. The `/foo/i` syntax is useful when writing
case-insensitive regular expressions for the `matches` operator.

YARA’s regular expressions recognise the following metacharacters:

| Character | Meaning                                                                                                                  | 
|-----------|--------------------------------------------------------------------------------------------------------------------------|
| `\`       | Quote the next metacharacter                                                                                             | 
| `^`       | Match the beginning of the data, or negates a character class when used as the first character after the opening bracket |
| `$`       | Match the end of the data                                                                                                |
| `.`       | Matches any single character except a newline character                                                                  |
| `\|`      | Alternation                                                                                                              |                                                                                                               |
| `()`      | Grouping                                                                                                                 |
| `[]`      | Bracketed character class                                                                                                |

The following quantifiers are recognized as well:

```text
x*        zero or more of x (greedy)
x+        one or more of x (greedy)
x?        zero or one of x (greedy)
x*?       zero or more of x (ungreedy/lazy)
x+?       one or more of x (ungreedy/lazy)
x??       zero or one of x (ungreedy/lazy)
x{n,m}    at least n x and at most m x (greedy)
x{n,}     at least n x (greedy)
x{,m}     at most m x (greedy)
x{n}      exactly n x
x{n,m}?   at least n x and at most m x (ungreedy/lazy)
x{n,}?    at least n x (ungreedy/lazy)
x{,m}?    at most m x (ungreedy/lazy)
x{n}?     exactly n x
```

The following escape sequences are recognized:

```text
\*              literal *, applies to all ASCII except [0-9A-Za-z<>]
\a              bell (\x07)
\f              form feed (\x0C)
\t              horizontal tab
\n              new line
\r              carriage return
\v              vertical tab (\x0B)
\A              matches at the beginning of a haystack
\z              matches at the end of a haystack
\b              word boundary assertion
\B              negated word boundary assertion
\b{start},      start-of-word boundary assertion
\b{end},        end-of-word boundary assertion
\b{start-half}  half of a start-of-word boundary assertion
\b{end-half}    half of a end-of-word boundary assertion
\123            octal character code, up to three digits (when enabled)
\x7F            hex character code (exactly two digits)
\x{10FFFF}      any hex character code corresponding to a Unicode code point
\u007F          hex character code (exactly four digits)
\u{7F}          any hex character code corresponding to a Unicode code point
\U0000007F      hex character code (exactly eight digits)
\U{7F}          any hex character code corresponding to a Unicode code point
\p{Letter}      Unicode character class
\P{Letter}      negated Unicode character class
\d              match a decimal digit
\s              match a whitespace character
\w              match a word character (alphanumeric or `_`)
\D              negated \d, matches a non-decimal digit
\S              negated \s, matches a non-whitespace character
\W              negated \w, matches a non-word character
```
