---
title: "Rule conditions"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "conditions"
weight: 250
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The condition is the part of the rule that states under which circumstances.
the rule matches. It can contain the typical boolean operators `and`, `or`,
and `not`, and relational operators `>=`, `<=`, `<`, `>`, `==` and `!=`. Also,
the arithmetic operators (`+`, `-`, `*`, `\`, `%`) and bitwise operators (`&`,
`|`, `<<`, `>>`, `~`, `^`) can be used on numerical expressions.

Pattern identifiers are used in conditions, acting as boolean variables whose
value depends on the presence of the associated pattern in the scanned data.
If the pattern is found in the data, the corresponding variable will be `true`,
and `false` if otherwise.

```yara
rule Example {
    strings:
        $a = "text1"
        $b = "text2"
        $c = "text3"
        $d = "text4"
    condition:
        ($a or $b) and ($c or $d)
}
```

## Operators

The following table lists the precedence and associativity of all operators. The
table is sorted in descending precedence order. When parsing an expression,
operators with the highest precedence will be bound tighter (as if by
parentheses) to its arguments than any operator with a lower precedence. For
example, the expressions `1 << a & b` is parsed as `(1 << a) & b`

Operators that have the same precedence are bound to their arguments in the
direction of their associativity.

| Precedence | Operator      | Description                             | Associativity |
|------------|---------------|-----------------------------------------|---------------|
| 13         | `[]`          | Array subscripting                      | Left-to-right |
| 13         | `.`           | Struct member access                    | Left-to-right |
| 12         | `-`           | Unary minus                             | Right-to-left |
| 12         | `~`           | Bitwise not                             | Right-to-left |
| 11         | `*`           | Multiplication                          | Left-to-right |
| 11         | `\`           | Division                                | Left-to-right |
| 11         | `%`           | Remainder                               | Left-to-right |
| 10         | `+`           | Addition                                | Left-to-right |
| 10         | `-`           | Subtraction                             | Left-to-right |
| 9          | `<<`          | Bitwise shift-left                      | Left-to-right |
| 9          | `>>`          | Bitwise shift-right                     | Left-to-right |
| 8          | `&`           | Bitwise and                             | Left-to-right |
| 7          | `^`           | Bitwise xor                             | Left-to-right |
| 6          | `\|`          | Bitwise or                              | Left-to-right |
| 5          | `<`           | Less than                               | Left-to-right |
| 5          | `<=`          | Less than or equal to                   | Left-to-right |
| 5          | `>`           | Greater than                            | Left-to-right |
| 5          | `>=`          | Greater than or equal to                | Left-to-right |
| 4          | `==`          | Equal to                                | Left-to-right |
| 4          | `!=`          | Not equal to                            | Left-to-right |
| 4          | `contains`    | String contains substring               | Left-to-right |
| 4          | `icontains`   | Like `contains`, but case-insensitive   | Left-to-right |
| 4          | `startswith`  | String starts with substring            | Left-to-right |
| 4          | `istartswith` | Like `startswith`, but case-insensitive | Left-to-right |
| 4          | `endswith`    | String ends with substring              | Left-to-right |
| 4          | `endsswith`   | Like `endswith`, but case-insensitive   | Left-to-right |
| 4          | `iequals`     | Case-insensitive string comparison      | Left-to-right |
| 4          | `matches`     | String matches regular expression       | Left-to-right |
| 3          | `defined`     | Check is expression is defined          | Right-to-left |
| 3          | `not`         | Logical not                             | Right-to-left |
| 2          | `and`         | Logical and                             | Left-to-right |
| 1          | `or`          | Logical or                              | Left-to-right |

## Counting pattern occurrences

Sometimes we need to know not only if a certain pattern is present or not, but
how many times the pattern appears in the data. The number of occurrences of
each pattern is represented by a variable whose name is the pattern identifier
but with a `#` character in place of the `$` character. For example:

```yara
rule CountExample {
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        #a == 6 and #b > 10
}
```

The rule above rule matches if the data contains "dummy1" exactly six times,
and "dummy2" more than 10 times.

It's also possible to limit the occurrences to some offset range in the scanned
data. For instance, the condition below means that there must be exactly 2
occurrences of "dummy1" in the last 500 bytes of the data.

```
#a in (filesize-500..filesize) == 2
```

## Finding patterns at specific offsets

In most cases, when we use a pattern identifier in a condition, we want to check
if the associated pattern appears anywhere within the data. However, sometimes
we specifically need to know if the pattern is located at a particular position
in the data. In such cases, we use the `at` operator. Here's how it works:

```yara
rule AtExample {
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        $a at 100 and $b at 200
}
```

In this example, `$a at 100` evaluates to true only if the pattern `$a` is found
at offset 100 in the data, and `$b` should appear at offset 200. It's important
to note that both offsets are specified in decimal format, but hexadecimal
numbers can also be used by adding the prefix `0x` before the number, similar to
the convention in the C language. Additionally, remember that the `at` operator
takes precedence over the `and` operator.

While the `at` operator allows to search for a pattern at some fixed offset in
the data, the `in` operator allows to search for the pattern within a range of
offsets.

```yara
rule InExample {
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        $a in (0..100) and $b in (100..filesize)
}
```

In the example above the pattern `$a` must be found at some offset between 0 and
100, while pattern `$b` must be at some offset between 100 and the end of the
file. Again, numbers are decimal by default.

You can also get the offset of the i-th occurrence of pattern `$a` by using
`@a[i]`. The indexes are one-based, so the first occurrence would be `@a[1]`
the second one `@a[2]`, and so on. If you provide an index greater than the
number of occurrences of the pattern, the result will be a NaN (Not A Number)
value.

## Match lengths

For many regular expressions and hex patterns containing jumps, the length of
the match will vary. If you have the regular expression `/fo*/` the strings "
fo", "foo" and "fooo" can be matches, all of them with a different length.

You can use the length of the match as part of your condition by using the
character `!` in front of the pattern identifier, in a similar way you use
the `@` character for the offset. `!a[1]` is the length for the first match of
`$a`, `!a[2]` is the length for the second match, and so on. `!a` is an
abbreviated form of `!a[1]`.

Integers are always 64-bits long, even the results of functions like `uint8`,
`uint16` and `uint32` are promoted to 64-bits. This is something you must take
into account, specially while using bitwise operators (for example, `~0x01` is
not `0xFE` but `0xFFFFFFFFFFFFFFFE`).

The following table lists the precedence and associativity of all operators. The
table is sorted in descending precedence order, which means that operators
listed on a higher row in the list are grouped prior operators listed in rows
further below it. Operators within the same row have the same precedence, if
they appear together in a expression the associativity determines how they are
grouped.

## File size

Pattern identifiers are not the only variables that can appear in a condition (
in fact, rules can be defined without patterns, as will be shown below), there
are other special variables that can be used as well. One of these special
variables is `filesize`, which holds, as its name indicates, the size of
the file being scanned. The size is expressed in bytes.

```yara
rule FileSizeExample {
    condition:
        filesize > 200KB
}
```

The previous example also demonstrates the use of the `KB` postfix. This
postfix, when attached to a numerical constant, automatically multiplies the
value of the constant by 1024. The MB postfix can be used to multiply the value
by 2^20. Both postfixes can be used only with decimal constants.

## Reading data at a given offset

There are many situations in which you may want to write conditions that depend
on data stored at a certain file offset. In those situations you can use one of
the following functions to read data from the file at the given offset:

```text
int8(<offset>)
int16(<offset>)
int32(<offset>)

uint8(<offset>)
uint16(<offset>)
uint32(<offset>)

int8be(<offset>)
int16be(<offset>)
int32be(<offset>)

uint8be(<offset>)
uint16be(<offset>)
uint32be(<offset>)
```

The `intXX` functions read 8, 16, and 32 bits signed integers from the given
offset, while functions uintXX read unsigned integers. Both 16 and 32-bit
integers are considered to be little-endian. If you want to read a big-endian
integer use the corresponding function ending in `be`. The offset parameter can
be any expression returning an unsigned integer, including the return value of
one the `uintXX` functions. Let's see a rule to distinguish PE files:

```yara
rule IsPE {
    condition:
        // MZ signature at offset 0 and ...
        uint16(0) == 0x5A4D and
        // ... PE signature at offset stored in MZ header at 0x3C
        uint32(uint32(0x3C)) == 0x00004550
}
```

## Sets of patterns

There are circumstances in which it is necessary to express that the data should
contain a certain number patterns from a given set. None of the patterns in the
set are required to be present, but at least some of them should be. In these
situations the `of` operator can be used.

```yara
rule OfExample1 {
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"
    condition:
        2 of ($a, $b, $c)
}
```

This rule requires that at least two of the patterns in the set `($a, $b, $c)`
must be present in the data, but it does not matter which two. Of course, when
using this operator, the number before the `of` keyword must be less than or
equal to the number of patterns in the set.

The elements of the set can be explicitly enumerated like in the previous
example, or can be specified by using wildcards. For example:

```yara
rule OfExample2{
    strings:
        $foo1 = "foo1"
        $foo2 = "foo2"
        $foo3 = "foo3"
    condition:
        2 of ($foo*)  // equivalent to 2 of ($foo1,$foo2,$foo3)
}

rule OfExample3 {
    strings:
        $foo1 = "foo1"
        $foo2 = "foo2"
        $bar1 = "bar1"
        $bar2 = "bar2"
    condition:
        3 of ($foo*, $bar1, $bar2)
}
```

You can even use `($*)` to refer to all the patterns in your rule, or write the
equivalent keyword `them` for more legibility.

```yara
rule OfExample4 {
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"
    condition:
        1 of them // equivalent to 1 of ($*)
}
```

In all the examples above, the number of patterns have been specified by a
numeric constant, but any expression returning a numeric value can be used. The
keywords `any`, `all` and `none` can be used as well.

```yara
all of them       // all patterns in the rule
any of them       // any patterns in the rule
all of ($a*)      // all patterns whose identifier starts by $a
any of ($a,$b,$c) // any of $a, $b or $c
1 of ($*)         // same that "any of them"
none of ($b*)     // none of the set of patterns that start with "$b"
```

{{< callout title="Warning">}}

Using `0 of them` is an ambiguous part of the language which should be avoided
in favor of `none of them`. To grasp this, let's consider the meaning
of `2 of them`, which is true if two or more of the patterns match.
Historically, `0 of them` followed this principle and would evaluate to true if
at least one of the patterns matched. This ambiguity was resolved in YARA 4.3.0
by making `0 of them` evaluate to true if exactly zero patterns match. To
enhance clarity and avoid confusion, it's recommended to use `none` instead of
`0`. This way it's easier to reason about the meaning of the statement.

{{< /callout >}}

It's also possible to search for a set of patterns in an offset range, like
this:

```yara
all of ($a*) in (filesize-500..filesize)
any of ($a*, $b*) in (1000..2000)
```

Or in a specific offset, like this:

```yara
any of ($a*) at 0
```

## Applying the same condition to many patterns

There is another operator very similar to `of` but even more powerful,
the `for..of` operator. The syntax is:

```yara
for <quantifier> of <pattern_set> : ( <boolean_expression> )
```

And it means: from those patterns in `<pattern_set>`, at least `<quantifier>` of
them must satisfy `<boolean_expression>`. In other words: `<boolean_expression>`
is evaluated for every pattern in `<pattern_set>` and there must be at
least `<quantifier>` of them returning true.

Of course, `<boolean_expression>` can be any boolean expression accepted in the
condition section of a rule, except for one important detail: here you can (and
should) use a dollar sign (`$`) as a place-holder for the pattern being
evaluated.

Take a look at the following expression:

```yara
for any of ($a, $b, $c) : ( $ at pe.entry_point  )
```

The `$` symbol in the boolean expression is not tied to any particular pattern,
it will be `$a`, and then `$b`, and then `$c` in the three successive
evaluations of the expression.

Maybe you already realised that the `of` operator is a special case
of `for..of`. The following expressions are the same:

```yara
any of ($a, $b, $c)
```

```yara
for any of ($a, $b, $c) : ( $ )
```

You can also employ the symbols `#`, `@`, and `!` to make reference to the
number of occurrences, the first offset, and the length of each pattern
respectively.

```yara
for all of them : ( # > 3 )
```

```yara
for all of ($a*) : ( @ > @b )
```

## Anonymous patterns

When using the `of` and `for..of` operators followed by `them`, the identifier
assigned to each pattern in the rule is usually superfluous. As we are not
referencing any pattern individually we do not need to provide a unique
identifier for each of them. In those situations you can declare anonymous
patterns with identifiers consisting only of the `$` character, as in the
following example:

```yara
rule AnonymousStrings {
    strings:
        $ = "dummy1"
        $ = "dummy2"
    condition:
        1 of them
}
```

## Iterating over pattern occurrences

As seen in [Finding patterns at specific
offsets](#finding-patterns-at-specific-offsets), the offsets where a given
patternst appears can be accessed by using the syntax: `@a[i]`, where `i` is
an index indicating which occurrence of the pattern `$a` you are referring to.
(`@a[1]`, `@a[2]`,...). Sometimes you will need to iterate over some of these
offsets and guarantee they satisfy a given condition. In such cases you can use
the `for..in` syntax, for example:

```yara
rule Occurrences {
    strings:
        $a = "dummy1"
        $b = "dummy2"
    condition:
        for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )
}
```

The previous rule says that the first occurrence of `$b` should be 10 bytes
after
the first occurrence of `$a`, and the same should happen with the second and
third
occurrences of the two patterns.

The same condition could be written also as:

`for all i in (1..3) : ( @a[i] + 10 == @b[i] )`

Notice that we’re using a range `(1..3)` instead of enumerating the index values
`(1,2,3)`. Of course, we’re not forced to use constants to specify range
boundaries, we can use expressions as well, as in the following example:

`for all i in (1..#a) : ( @a[i] < 100 )`

In this case we’re iterating over every occurrence of `$a` (remember that `#a`
represents the number of occurrences of `$a`). This rule is specifying that
every occurrence of `$a` should be within the first 100 bytes of the file.

In case you want to express that only some occurrences of the pattern should
satisfy your condition, the same logic seen in the `for..of` operator applies
here:

`for any i in (1..#a) : ( @a[i] < 100 )`

`for 2 i in (1..#a) : ( @a[i] < 100 )`

The `for..in` operator is similar to `for..of`, but the latter iterates over a
set of patterns, while the former iterates over ranges, enumerations, arrays
and dictionaries.

## The "with" statement

YARA-X now supports the `with` statement defined by [RFC](https://github.com/VirusTotal/yara/discussions/1783), which allows you to define identifiers
that holds the result of a boolean expression. Each identifier is local and is
valid only within the `with` statement. The syntax is: 

```yara
with 
    <identifier> = <expression> [,<identifier> = <expression>]* : 
    (
        <boolean expression>
    )
```

For example:

```yara
rule WithExample {
    condition:
        with
            first = foo.bar[0],
            last = foo.bar[num_of_items - 1] : (
                first.text == last.text
            )
}
```

Using the `with` identifier outside of a `with` statement is not allowed.
Something like:
    
```yara
rule WithExample {
    condition:
        with
            first = foo.bar[0],
            last = foo.bar[num_of_items - 1] : (
                first.text == last.text
            )
        or last.text != first.text
}    
```

is syntactically valid but it will raise a compilation error.

Another usage of the `with` statement could be to avoid repeating the same
expression multiple times in the condition. Something like:

```yara
pe.sections[0] .name == ".text" and
pe.sections[0].characteristics == 0xC0000000 and
pe.sections[0].raw_data_size == 0x2000 and
pe.sections[0].raw_data_offset == 0x1000 and
pe.sections[pe.number_of_sections - 1] .name == ".tls" and
pe.sections[pe.number_of_sections - 1].characteristics == 0xC0000000 and
pe.sections[pe.number_of_sections - 1].raw_data_size == 0x1000 and
pe.sections[pe.number_of_sections - 1].raw_data_offset == 0x4000
```

can be rewritten as:

```yara
with 
    fs = pe.sections[0], 
    ls = pe.sections[pe.number_of_sections - 1] : (
        fs.name == ".text" and
        fs.name.characteristics == 0xC0000000 and
        fs.name.raw_data_size == 0x2000 and
        fs.name.raw_data_offset == 0x1000 and
        ls.name == ".tls" and
        ls.characteristics == 0xC0000000 and
        ls.raw_data_size == 0x1000 and
        ls.raw_data_offset == 0x4000
    )
```

Another use case is to declare a variable that is used just in "for" loops:

```yara
for all offset in (10,20,30) : (
    with val = uint64(offset) | uint64(offset + 4) | uint64(offset + 8) : (
        val == 0x10000 or 
        val == 0x20000 or 
        val == 0x40000
  )
)
```

## Referencing other rules

When writing the condition for a rule, you can also make reference to a
previously defined rule in a manner that resembles a function invocation of
traditional programming languages. In this way you can create rules that depend
on others. Let's see an example:

```yara
rule Rule1 {
    strings:
        $a = "dummy1"
    condition:
        $a
}

rule Rule2 {
    strings:
        $a = "dummy2"
    condition:
        $a and Rule1
}
```

As can be seen in the example, a file will satisfy `Rule2` only if it contains
the string `dummy2` and satisfies `Rule1`. Note that it is strictly necessary to
define the rule being invoked before the one that will make the invocation.


