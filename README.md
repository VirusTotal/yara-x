## What's YARA-X?

This is an experimental project for evaluating the feasibility of writing a 
full-fledged implementation of YARA in Rust. For the time being don't take this
project very seriously, it may be abandoned at any time if it doesn't prove to
be worth the effort.

However, I would like to get something useful out of this, so the intention is
at the very least implementing a code formatting tool for YARA in the spirit of
`rustfmt` and `gofmt`. In the best case scenario this could evolve into becoming
a serious replacement for YARA.


## Changes with respect to YARA 4.x

This section describes the differences that YARA-X has with respect to YARA 4.x
so far. These differences are not set in stone yet and may change in the future.

### Negative numbers are not accepted in array indexing
  
The expression `@a[-1]` is valid in YARA 4.x, but its value is always
`undefined`. In YARA-X this is an error.

### Integers and strings are not promoted automatically to booleans

This rule is valid in YARA 4.x because the integer expression `2` is promoted
to `true`.

```yara
rule type_promotion_example {
  condition:
    2
}
```

This however can lead to subtle errors due to the unintended use of integers 
or strings as booleans.

### Duplicate rule modifiers are not accepted

In YARA 4.x rules can have any number of `global` or `private`, for example the
following is valid:

```yara
global global global rule duplicated_global  {
   ... 
}
```

In YARA-X you can specify each modifier once. They can still appear in any order,
though.


### `<quantifier> of <tuple>` statements accept tuples of boolean expressions

In YARA 4.x the `of` statement accepts a tuple of string or rule identifiers. 
In both cases the identifiers can contain wildcards. For example both of these 
are valid:

```yara
1 of ($a, $c, $b*, $*)
```

```yara
1 of (some_rule, another_rule*)
```

The first case remains the same, but the second one has been generalized to
accept arbitrary boolean expressions, like in...

```yara
1 of (true, false)
```

```yara
1 of ($a and not $b, $c, false)
```

Notice however that we have lost the possibility of using wildcards with rule
names. So, this is valid...

```yara
1 of (some_rule)
```

But this is not valid...

```yara
1 of (some_rule*)
```
