---
title: "Warnings"
description: "Reference for all YARA-X compiler warning codes"
summary: ""
date: 2026-10-05T13:00:00+02:00
lastmod: 2026-10-05T13:00:00+02:00
draft: false
url: "/docs/warnings/"
menu:
  docs:
    parent: ""
    identifier: "warnings-reference"
weight: 200
toc: true
seo:
  title: "Compiler Warnings"
  description: "Reference for all YARA-X compiler warning codes"
  noindex: false
---

The YARA-X compiler emits warnings to help catch common mistakes, performance
pitfalls, and redundant constructs in rules. Each warning has a unique identifier
that can also be used to [disable or suppress warnings]({{< ref "/docs/writing_rules/disabling_warnings.md" >}}).

## ambiguous_expr {#ambiguous_expr}

An ambiguous expression is used in a rule condition. For example, writing
`0 of them` can be ambiguous about whether no patterns should match; using
`none of them` expresses the intent clearly.

```text
warning[ambiguous_expr]: ambiguous expression
 --> line:6:5
  |
6 |     0 of them
  |     --------- this expression is ambiguous
  |
help: consider using `none` instead of `0`
  |
6 - 0 of them
6 + none of them
  |
```

## bool_int_comparison {#bool_int_comparison}

A boolean expression is being compared directly with an integer value (such as
`== 1` or `== 0`), which can be simplified to a boolean expression.

```text
warning[bool_int_comparison]: comparison between boolean and integer
 --> line:4:13
  |
4 |  condition: pe.is_pe == 1
  |             ------------- this is comparing an integer and a boolean
  |
```

## consecutive_jumps {#consecutive_jumps}

A hex pattern contains two or more consecutive jumps. For instance, in
`{ 01 02 [0-2] [1-3] 03 04 }`, the jumps `[0-2]` and `[1-3]` appear one after
the other. Consecutive jumps are redundant and can be folded into a single jump
(in this case `[1-5]`).

```text
warning[consecutive_jumps]: consecutive jumps in hex pattern `$a`
 --> line:3:18
  |
3 |     $a = { 0F 84 [4] [0-7] 8D }
  |                  --------- these consecutive jumps will be treated as [4-11]
  |
```

## deprecated_field {#deprecated_field}

A deprecated module field was used in a YARA rule. Check the warning label for
the recommended replacement field.

```text
warning[deprecated_field]: field `foo` is deprecated
 --> rules/test.yara:3:13
  |
3 | vt.metadata.foo
  |             --- `foo` is deprecated, use `bar` instead
  |
```

## duplicate_import {#duplicate_import}

The same module was imported multiple times in the same source file.

```text
warning[duplicate_import]: duplicate import statement
 --> line:2:1
  |
1 | import "pe"
  | ----------- note: `pe` imported here for the first time
2 | import "pe"
  | ----------- duplicate import
  |
```

## duplicate_pattern_value {#duplicate_pattern_value}

Two or more patterns in the same rule have identical literal or regular
expression values and modifiers, leading to redundant scanning work.

```text
warning[duplicate_pattern_value]: duplicate pattern value
 --> test.yar:4:9
  |
3 |         $a = "exact_duplicate_string"
  |              ------------------------ pattern `$a` defined here first
4 |         $b = "exact_duplicate_string"
  |              ------------------------ duplicate of pattern `$a`
  |
```

## global_rule_misuse {#global_rule_misuse}

A global rule is explicitly referenced inside another rule's condition. Global
rules are already implicit prerequisites for all non-global rules, so checking
them explicitly is redundant, and negating a global rule makes the condition
unsatisfiable.

```text
warning[global_rule_misuse]: global rule used in condition
 --> line:7:5
  |
7 |     global_rule_1
  |     ------------- a global rule is being used as part of an condition
  |
  = note: referencing a global rule in a condition is redundant, and may result in an unsatisfiable condition
```

## greedy_dot_star {#greedy_dot_star}

A regular expression contains a greedy `.*` repetition, which can cause
performance issues due to excessive backtracking. Consider using the non-greedy
`.*?` variant instead.

```text
warning[greedy_dot_star]: greedy `.*` in pattern `$a`
 --> line:3:14
  |
3 |     $a = /foo.*bar/
  |              -- consider using `.*?` instead
  |
```

## ignored_rule {#ignored_rule}

A rule will be ignored because it depends on another rule that uses an
unsupported (ignored) module.

```text
warning[ignored_rule]: rule `foo` will be ignored due to an indirect dependency on module `magic`
 --> line:9:5
  |
9 |     bar
  |     --- this other rule depends on module `magic`, which is unsupported
  |
```

## invalid_metadata {#invalid_metadata}

A metadata entry does not satisfy the requirements configured for the metadata
linter (such as value type or regular expression format).

```text
warning[invalid_metadata]: metadata `author` is not valid
 --> test.yar:4:5
  |
4 |     author = 1234
  |              ---- `author` must be a string
  |
```

## invalid_rule_name {#invalid_rule_name}

A rule's identifier does not match the regular expression configured in the
rule-name linter.

```text
warning[invalid_rule_name]: rule name does not match regex `APT_.*`
 --> test.yar:13:6
  |
13 | rule pants {
  |      ----- this rule name does not match regex `APT_.*`
  |
```

## invalid_tag {#invalid_tag}

A rule tag does not match the regular expression configured in the tag linter.

```text
warning[invalid_tag]: tag `foo` does not match regex `bar`
 --> rules/test.yara:1:10
  |
1 | rule a : foo {
  |          --- tag `foo` does not match regex `bar`
  |
```

## invariant_expr {#invariant_expr}

A boolean expression in a rule condition always evaluates to the same constant
value (`true` or `false`), regardless of the scanned data.

```text
warning[invariant_expr]: invariant boolean expression
 --> line:6:5
  |
6 |     3 of them
  |     --------- this expression is always false
  |
  = note: the expression requires 3 matching patterns out of 2
```

## missing_metadata {#missing_metadata}

A rule is missing a metadata entry that was configured as required by the
metadata linter.

```text
warning[missing_metadata]: required metadata is missing
 --> test.yar:12:6
  |
12 | rule pants {
  |      ----- required metadata `date` not found
  |
```

## non_bool_expr {#non_bool_expr}

A non-boolean expression (such as an integer) is used in a boolean context (like
an `and` or `or` operand). Consider writing an explicit comparison such as
`!= 0` for clarity.

```text
warning[non_bool_expr]: non-boolean expression used as boolean
 --> line:3:14
  |
3 |   condition: 2 and 3
  |              - this expression is `integer` but is being used as `bool`
  |
  = note: non-zero integers are considered `true`, while zero is `false`
```

## potentially_slow_loop {#potentially_slow_loop}

A rule contains a `for` loop that iterates over a range whose upper bound
depends on `filesize` (or another unbounded value). On large files, this can
result in hundreds of millions of iterations and significantly slow down
scanning.

```text
warning[potentially_slow_loop]: potentially slow loop
 --> test.yar:1:34
  |
1 | rule t { condition: for any i in (0..filesize-1) : ( int32(i) == 0xcafebabe ) }
  |                                  --------------- this range can be very large
  |
```

## redundant_modifier {#redundant_modifier}

Both the `/i` regular expression suffix and the `nocase` keyword modifier were
used on the same regular expression pattern. Because both make the pattern
case-insensitive, using both together is redundant.

```text
warning[redundant_modifier]: redundant case-insensitive modifier
 --> line:3:15
  |
3 |     $a = /foo/i nocase
  |               - the `i` suffix indicates that the pattern is case-insensitive
  |                 ------ the `nocase` modifier does the same
  |
```

## slow_pattern {#slow_pattern}

A pattern may be slow to match and degrade scanning performance. This is
typically caused by patterns that do not contain any fixed sub-pattern (atom)
long enough to narrow down candidate matches efficiently.

```text
warning[slow_pattern]: slow pattern
 --> line:3:5
  |
3 |     $a = { 00 [1-10] 01 }
  |     --------------------- this pattern may slow down the scan
  |
```

## text_as_hex {#text_as_hex}

A hex pattern consists purely of printable ASCII bytes without wildcards or
jumps (for example, `{ 61 61 61 }`), and can be written more legibly as a text
literal (`"aaa"`).

```text
warning[text_as_hex]: hex pattern could be written as text literal
 --> test.yar:6:4
  |
6 |    $d = { 61 61 61 }
  |    ----------------- this pattern can be written as a text literal
```

## too_many_iterations {#too_many_iterations}

A `for` loop or a set of nested `for` loops has a total number of iterations
exceeding a predefined threshold, which can make rule evaluation slow.

```text
warning[too_many_iterations]: loop has too many iterations
 --> test.yar:1:20
  |
1 | rule t { condition: for any i in (0..1000) : ( for any j in (0..1000) : ( true ) ) }
  |                    -------------------------------------------------------------- this loop iterates 1000000 times, which may be slow
  |
```

## unintended_pattern_in_set {#unintended_pattern_in_set}

A pattern is referenced individually in a condition and also matched by a
wildcard pattern set (such as `$s*`) in the same expression. For instance, if a
rule defines `$s1`, `$s2`, and `$start_bytes`, the condition
`$start_bytes and any of ($s*)` unintentionally includes `$start_bytes` in
`($s*)`.

```text
warning[unintended_pattern_in_set]: pattern `$start_bytes` may be unintendedly or redundantly included in pattern set `$s*`
 --> line:8:5
  |
8 |     $start_bytes and any of ($s*)
  |     ------------             --- `$start_bytes` is also included in `$s*`
  |     |
  |     `$start_bytes` is used here
```

## unknown_tag {#unknown_tag}

A rule uses a tag that is not in the list of allowed tags configured for the tag
linter.

```text
warning[unknown_tag]: tag not in allowed list
 --> rules/test.yara:1:10
  |
1 | rule a : foo {
  |          --- tag `foo` not in allowed list
  |
  = note: allowed tags: test, bar
```

## unsatisfiable_expr {#unsatisfiable_expr}

A boolean expression in a condition cannot possibly be satisfied (or is almost
certainly unsatisfiable). Examples include comparing a lowercase hash function
result with an uppercase string literal, or requiring multiple distinct patterns
to match at the same offset (`2 of ($*) at 0`).

```text
warning[unsatisfiable_expr]: unsatisfiable expression
 --> test.yar:6:34
  |
6 | rule x { condition: "AD" == hash.sha256(0,filesize) }
  |                     ----         ------------------ this is a lowercase string
  |                     |
  |                     this contains uppercase characters
  |
  = note: a lowercase string can't be equal to a string containing uppercase characters
```

## unsupported_module {#unsupported_module}

A rule uses a module that has been marked as ignored via the compiler's ignored
modules configuration. The rule using that module will be ignored.

```text
warning[unsupported_module]: module `magic` is not supported
 --> line:4:5
  |
4 |     magic.type()
  |     ----- module `magic` used here
  |
  = note: the whole rule `foo` will be ignored
```

## unused_identifier {#unused_identifier}

An identifier was declared in a `with` statement, but is never used in its body
expression.

```text
warning[unused_identifier]: unused identifier
 --> test.yar:6:32
  |
6 |             with a = 1, b = 2, c = 3 : ( a + b == 3 )
  |                                - this identifier declared but not used
```
