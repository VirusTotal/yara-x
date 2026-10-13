---
title: "Errors"
description: "Reference for all YARA-X compiler error codes"
summary: ""
date: 2026-10-05T13:00:00+02:00
lastmod: 2026-10-05T13:00:00+02:00
draft: false
url: "/docs/errors/"
menu:
  docs:
    parent: ""
    identifier: "errors-reference"
weight: 100
toc: true
seo:
  title: "Compiler Errors"
  description: "Reference for all YARA-X compiler error codes"
  noindex: false
---

Each error raised by the YARA-X compiler is identified by a unique error code
ranging from `E001` to `E047`. This page explains the cause of each error along
with an example.

## E001 {#E001}

A syntax error was found while parsing a YARA rule. This happens when the source
code does not conform to the YARA grammar, such as missing keywords, unexpected
tokens, or unclosed delimiters.

```text
error[E001]: syntax error
 --> line:3:5
  |
3 |     !
  |     ^ this `!` is outside of the body of a `for .. of` statement
```

## E002 {#E002}

An expression has a different type from what is expected in that context. For
example, range bounds, array indices, and file offsets must evaluate to an
`integer`.

```text
error[E002]: wrong type
 --> line:5:15
  |
5 |     #a in (0.."10")
  |               ^^^^ expression should be `integer`, but it is `string`
```

## E003 {#E003}

Two or more operands or elements in an expression have incompatible types. For
instance, all items in a tuple used by a `for .. in` loop must share the same
type, and comparison operators require compatible operand types.

```text
error[E003]: mismatching types
 --> line:3:20
  |
4 |     for 1 n in (1, 2, "3") : (
  |                    ^  ^^^ this expression is `string`
  |                    |
  |                    this expression is `integer`
```

## E004 {#E004}

A function or method was called with the wrong number or types of arguments. The
error note lists the argument combinations accepted by the function.

```text
error[E004]: wrong arguments
 --> line:4:20
  |
4 |     math.entropy("invalid") == 0
  |                 ^^^^^^^^^^^ wrong arguments in this call
  |
  = note: accepted argument combinations:

          (integer, integer)
          (string)
```

## E005 {#E005}

The number of loop variables declared in a `for .. in` expression does not match
the number of values produced by the iterable expression. For example, iterating
over a range produces a single integer per iteration, whereas iterating over a
map produces a key-value pair (two values).

```text
error[E005]: assignment mismatch
 --> line:3:13
  |
3 |     for all x,y in (0..10) : ( true )
  |             ^^^    ^^^^^^^ this produces 1 value(s)
  |             |
  |             this expects 2 value(s)
```

## E006 {#E006}

A negative number was used in a context where only non-negative integers are
allowed, such as file offsets (`at`) or occurrence counts.

```text
error[E006]: unexpected negative number
 --> line:6:11
  |
6 |     $a at -1
  |           ^^ this number can not be negative
```

## E007 {#E007}

An integer value or constant expression result falls outside the allowed range
for the operation. For instance, pattern occurrence indices (`@a[i]` or `!a[i]`)
are 1-based and must be at least `1`, and arithmetic operations on constants
cannot overflow a 64-bit signed integer.

```text
error[E007]: number out of range
 --> line:5:8
  |
5 |     @a[0]
  |        ^ this number is out of the allowed range [1-9223372036854775807]
```

## E008 {#E008}

A structure field or method referenced in a rule condition does not exist in the
module or structure.

```text
error[E008]: unknown field or method `foo`
 --> line:4:17
  |
4 |     pe.foo
  |        ^^^ this field or method doesn't exist
```

## E009 {#E009}

An identifier referenced in a condition has not been declared. This can happen
if a module was not imported with `import "..."`, a rule or loop variable name
was misspelled, or an external variable was not defined.

```text
error[E009]: unknown identifier `y`
 --> line:7:11
  |
7 |       and y == 1
  |           ^ this identifier has not been declared
```

## E010 {#E010}

An `import` statement references a module name that is not recognized by YARA-X.

```text
error[E010]: unknown module `foo`
 --> line:1:1
  |
1 | import "foo"
  | ^^^^^^^^^^^^ module `foo` not found
```

## E011 {#E011}

A range expression `(start..end)` or hex jump `[start-end]` is invalid—for
example, because its lower bound is greater than its upper bound.

```text
error[E011]: invalid range
 --> line:5:11
  |
5 |     $a in (2..1)
  |           ^^^^^^ lower bound (2) is greater than upper bound (1)
```

## E012 {#E012}

Two rules in the same namespace have the same name. Rule identifiers must be
unique within a namespace.

```text
error[E012]: duplicate rule `test`
 --> line:5:6
  |
1 | rule test {
  |      ---- `test` declared here for the first time
...
5 | rule test {
  |      ^^^^ duplicate declaration of `test`
```

## E013 {#E013}

A rule has the same name as an imported module or a defined external variable.

```text
error[E013]: rule `foo` conflicts with an existing identifier
 --> line:1:6
  |
1 | rule foo  {condition: true}
  |      ^^^ identifier already in use by a module or global variable
```

## E014 {#E014}

A regular expression has invalid syntax, such as an unclosed character class,
an unescaped `{` outside a repetition quantifier, or an invalid repetition range.

```text
error[E014]: invalid regular expression
 --> line:3:14
  |
3 |     $a = /abc[xyz/
  |              ^ unclosed character class
```

## E015 {#E015}

A regular expression mixes greedy (e.g., `.*`, `.+`) and non-greedy (e.g.,
`.*?`, `.+?`) quantifiers, which is not supported by YARA-X.

```text
error[E015]: mixing greedy and non-greedy quantifiers in regular expression
 --> line:3:12
  |
4 |     $a = /a.*b.*?c/
  |            ^^ ^^^ this is non-greedy
  |            |
  |            this is greedy
```

## E016 {#E016}

A pattern wildcard set (such as `($a*)`) does not match any pattern defined in
the `strings` section of the rule.

```text
error[E016]: no matching patterns
 --> line:3:13
  |
3 |     all of ($a*)
  |             ^^^ there's no pattern in this set
  |
  = note: `$a*` doesn't match any pattern identifier
```

## E017 {#E017}

The deprecated `entrypoint` keyword was used in a rule condition. Use format-specific
entry point fields such as `pe.entry_point`, `elf.entry_point`, or
`macho.entry_point` instead.

```text
error[E017]: `entrypoint` is unsupported
 --> line:3:5
  |
3 |     entrypoint == 0x1000
  |     ^^^^^^^^^^ the `entrypoint` keyword is not supported anymore
  |
help: use `pe.entry_point`, `elf.entry_point` or `macho.entry_point`
  |
3 -     entrypoint == 0x1000
3 +     pe.entry_point == 0x1000
  |
```

## E018 {#E018}

A pattern is rejected because it can severely degrade scanning performance (for
example, when strict slow-pattern checks are enabled or a pattern lacks usable
atoms).

```text
error[E018]: slow pattern
 --> line:3:5
  |
3 |     $a = { 00 [1-10] 01 }
  |     ^^^^^^^^^^^^^^^^^^^^^ this pattern may slow down the scan
```

## E019 {#E019}

Two incompatible modifiers were applied to the same pattern (for example,
combining `xor` with `nocase` or `base64` with `fullword`).

```text
error[E019]: invalid modifier combination: `xor` `nocase`
 --> line:3:16
  |
3 |     $a = "foo" xor nocase
  |                ^^^ ^^^^^^ `nocase` modifier used here
  |                |
  |                `xor` modifier used here
  |
  = note: these two modifiers can't be used together
```

## E020 {#E020}

The same modifier was specified more than once on a single pattern.

```text
error[E020]: duplicate pattern modifier
 --> line:3:23
  |
3 |     $a = "foo" xor(0) xor(1-2)
  |                       ^^^^^^^^ duplicate modifier
```

## E021 {#E021}

A rule declaration repeats the same tag more than once.

```text
error[E021]: duplicate tag `tag1`
 --> line:1:18
  |
1 | rule test : tag1 tag1 { condition: true }
  |                  ^^^^ duplicate tag
```

## E022 {#E022}

A pattern is defined in the `strings` section of a rule, but is never referenced
in the `condition` section. If a pattern is intentionally unused, prefix its
identifier with an underscore (e.g., `$_c = "baz"`).

```text
error[E022]: unused pattern `$c`
 --> line:5:6
  |
5 |      $c = "baz"
  |      ^^ this pattern was not used in the condition
```

## E023 {#E023}

Two patterns within the same rule share the same identifier. Only anonymous
patterns (`$ = ...`) may omit a unique name.

```text
error[E023]: duplicate pattern `$a`
 --> line:4:6
  |
3 |      $a = "foo"
  |      -- `$a` declared here for the first time
4 |      $a = "bar"
  |      ^^ duplicate declaration of `$a`
```

## E024 {#E024}

A pattern definition is invalid—for instance, a `base64` pattern shorter than 3
bytes, or a hex pattern with invalid jumps or wildcards at the start or end.

```text
error[E024]: invalid pattern `$a`
 --> line:3:10
  |
3 |     $a = "aa" base64
  |          ^^^^ this pattern is too short
  |
  = note: `base64` requires that pattern is at least 3 bytes long
```

## E025 {#E025}

A rule condition references a pattern identifier (such as `$a`, `#a`, `@a`, or
`!a`) that was not declared in the `strings` section.

```text
error[E025]: unknown pattern `$a`
 --> line:3:6
  |
3 |      $a
  |      ^^ this pattern is not declared in the `strings` section
```

## E026 {#E026}

The custom alphabet passed to the `base64` or `base64wide` modifier is invalid.
A custom base64 alphabet must be exactly 64 bytes long and contain no duplicate
characters.

```text
error[E026]: invalid base64 alphabet
 --> line:3:23
  |
3 |     $a = "foo" base64("ff")
  |                       ^^^^ invalid length - must be 64 bytes
```

## E027 {#E027}

An integer literal cannot be parsed—for example, because it exceeds the 64-bit
signed integer limits or contains invalid digits for its base.

```text
error[E027]: invalid integer
 --> line:2:15
  |
2 |    condition: 99999999999999999999
  |               ^^^^^^^^^^^^^^^^^^^^ this number is out of the valid range: [-9223372036854775808, 9223372036854775807]
```

## E028 {#E028}

A floating-point literal cannot be parsed as a valid 64-bit floating-point
number.

```text
error[E028]: invalid float
 --> line:2:15
  |
2 |    condition: 1.7976931348623159e309
  |               ^^^^^^^^^^^^^^^^^^^^^^ number would be infinite or NaN
```

## E029 {#E029}

A string or regular expression contains an invalid escape sequence, such as an
incomplete `\x` hex escape or an unrecognized escaped character when strict
escape checking is enabled.

```text
error[E029]: invalid escape sequence
 --> line:2:15
  |
2 |   condition: "\xZZ" == "\xZZ"
  |               ^^ expecting two hex digits after `\x`
```

## E030 {#E030}

A regular expression literal uses an unsupported suffix modifier. Only `/i`
(case-insensitive) and `/s` (dot matches newline) are valid regular expression
suffix modifiers.

```text
error[E030]: invalid regexp modifier `x`
 --> line:3:24
  |
3 |     "foo" matches /foo/x
  |                        ^ invalid modifier
```

## E031 {#E031}

An escape sequence was used in a string literal where escape sequences are not
permitted, such as in `import` or `include` statements or raw strings.

```text
error[E031]: unexpected escape sequence
 --> line:1:8
  |
1 | import "foo\x00"
  |        ^^^^^^^^^ escape sequences are not allowed in this string
```

## E032 {#E032}

The YARA source file or string literal contains invalid UTF-8 byte sequences.

```text
error[E032]: invalid UTF-8
 --> line:1:5
  |
1 | rule test {condition: true}
  |     ^ invalid UTF-8 character
```

## E033 {#E033}

A pattern modifier was applied to a pattern type that does not support it (for
example, `nocase` or `wide` on a hex pattern), or the modifier arguments are
invalid.

```text
error[E033]: invalid pattern modifier
 --> line:3:20
  |
3 |     $a = { 01 02 } nocase
  |                    ^^^^^^ this modifier can't be applied to a hex pattern
```

## E034 {#E034}

A rule contains a `for` loop that iterates over a range whose upper bound
depends on `filesize` (or another unbounded value) when potentially slow loops
are configured as errors. For large files, this can result in millions of
iterations.

```text
error[E034]: potentially slow loop
 --> test.yar:1:34
  |
1 | rule t { condition: for any i in (0..filesize-1) : ( int32(i) == 0xcafebabe ) }
  |                                  --------------- this range can be very large
  |
```

## E035 {#E035}

A single rule defines more patterns than the maximum allowed per rule.

```text
error[E035]: too many patterns in a rule
 --> test.yar:1:6
  |
1 | rule test {
  |      ^^^^ this rule has more than 64000 patterns
```

## E036 {#E036}

A method reference (uninvoked function or method) was assigned to a variable in
a `with` statement. Variables in `with` statements must hold concrete values
rather than method references.

```text
error[E036]: method not allowed in `with` statement
 --> line:7:18
  |
4 |       with foo = pe.exports : ( true )
  |                  ^^^^^^^^^^ this method is not allowed here
```

## E037 {#E037}

A metadata entry does not satisfy the requirements configured for the metadata
linter (for example, wrong value type or does not match the required regular
expression).

```text
error[E037]: metadata `author` is not valid
 --> test.yar:4:5
  |
4 |     author = 1234
  |              ---- `author` must be a string
  |
```

## E038 {#E038}

A rule is missing a metadata entry that was marked as required in the metadata
linter configuration.

```text
error[E038]: required metadata is missing
 --> test.yar:12:6
  |
12 | rule pants {
  |      ----- required metadata `date` not found
  |
```

## E039 {#E039}

A rule's identifier does not match the regular expression configured in the
rule-name linter.

```text
error[E039]: rule name does not match regex `APT_.*`
 --> test.yar:13:6
  |
13 | rule pants {
  |      ----- this rule name does not match regex `APT_.*`
  |
```

## E040 {#E040}

A rule uses a tag that is not in the list of allowed tags configured for the tag
linter.

```text
error[E040]: tag not in allowed list
 --> rules/test.yara:1:10
  |
1 | rule a : foo {
  |          ^^^ tag `foo` not in allowed list
  |
  = note: allowed tags: test, bar
```

## E041 {#E041}

A rule uses a tag that does not match the regular expression configured for the
tag linter.

```text
error[E041]: tag does not match regex `bar`
 --> rules/test.yara:1:10
  |
1 | rule a : foo {
  |          ^^^ tag `foo` does not match regex `bar`
  |
```

## E042 {#E042}

An I/O error occurred while reading a file referenced by an `include` statement.

```text
error[E042]: error including file
 --> line:1:1
  |
1 | include "rules.yar"
  | ^^^^^^^^^^^^^^^^^^^ failed with error: Permission denied (os error 13)
  |
```

## E043 {#E043}

The file specified in an `include` statement could not be found in the current
directory or any of the configured include directories.

```text
error[E043]: include file not found
 --> line:1:1
  |
1 | include "unknown.yar"
  | ^^^^^^^^^^^^^^^^^^^^^ `unknown.yar` not found in any of the include directories
  |
```

## E044 {#E044}

An `include` statement was encountered when `include` statements have been
explicitly disabled in the compiler configuration.

```text
error[E044]: include statements not allowed
 --> line:1:1
  |
1 | include "some_file.yar"
  | ^^^^^^^^^^^^^^^^^^^^^^^ includes are disabled for this compilation
```

## E045 {#E045}

A regular expression starts with an unanchored wildcard prefix such as `.*` or
`.+` that matches any sequence of bytes of arbitrary length. Such prefixes cause
the pattern to match at every file offset from the beginning of the file up to
where the remainder of the pattern matches, and can usually be removed without
changing the rule's meaning.

```text
error[E045]: arbitrary regular expression prefix
 --> line:3:11
  |
3 |     $a = /.*foo/s
  |           ^^ this prefix can be arbitrarily long and matches all bytes
  |
```

## E046 {#E046}

A cycle was detected in `include` statements (for example, file `a.yar` includes
`b.yar`, which in turn includes `a.yar`).

```text
error[E046]: circular include dependencies
 --> b.yar:1:1
  |
1 | include "a.yar"
  | ^^^^^^^^^^^^^^^ include statement has circular dependencies
```

## E047 {#E047}

A rule declares too many local variables in `with` or `for` statements,
exceeding the compiler's internal limit.

```text
error[E047]: too many variables
 --> line:4:7
  |
4 |       with v0=0, v1=0, ... : ( true )
  |            ^^^^^^^^^^^^^^^^^ too many local variables
```
