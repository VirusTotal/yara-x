[![tests](https://github.com/VirusTotal/yara-x/actions/workflows/tests.yaml/badge.svg)](https://github.com/VirusTotal/yara-x/actions/workflows/tests.yaml)
[![coverage](https://codecov.io/gh/VirusTotal/yara-x/branch/main/graph/badge.svg?token=dPsruCiDqN)](https://app.codecov.io/gh/VirusTotal/yara-x)

## What's YARA-X?

This is an experimental project for evaluating the feasibility of writing a 
full-fledged implementation of [YARA](https://github.com/VirusTotal/yara) in Rust. 
For the time being don't take this project very seriously, it may be abandoned 
at any time if it doesn't prove to be worth the effort.

However, I would like to get something useful out of this, so the intention is
at the very least implementing a code formatting tool for YARA in the spirit of
`rustfmt` and `gofmt`. In the best case scenario this could evolve into becoming
a serious replacement for YARA.

### Installation

Requires rustc 1.70.0 or newer

#### Linux

```bash
git clone https://github.com/VirusTotal/yara-x
cd yara-x
cargo build
./target/debug/yr --help
```

## Changes with respect to YARA 4.x

This section describes the differences that YARA-X has with respect to YARA 4.x
so far. These differences are not set in stone yet and may change in the future.

### Negative numbers are not accepted in array indexing
  
The expression `@a[-1]` is valid in YARA 4.x, but its value is always
`undefined`. In YARA-X this is an error.

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

```
1 of ($a, $c, $b*, $*)
```

```
1 of (some_rule, another_rule*)
```

The first case remains the same, but the second one has been generalized to
accept arbitrary boolean expressions, like in...

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

### `base64` modifier can't be used with strings shorter than 3 characters

In YARA 4.x you can use the `base64` modifier with strings shorter than 3 
characters, but this is an error in YARA-X. In the other hand, YARA-X won't
produce false positives when the `base64` modifiers is used, as it may happen 
in YARA 4.x in certain cases. This is a well-known YARA 4.x issue described in
the documentation:

> Because of the way that YARA strips the leading and trailing characters after base64 encoding, one of the base64 encodings of "Dhis program cannow" and "This program cannot" are identical.


### `base64` and `base64wide` modifiers can have different alphabets

In YARA 4.x if you use both `base64` and `base64wide` in the same string they
must use the same alphabet. If you specify a custom alphabet for `base64`, you
must do the same for `base64wide`, so this in error:

```
$a = "foo" base64 base64wide("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
```

In YARA-X you can specify different alphabets for `base64` and `base64wide` 
in the same string. In the example above `base64` would use the default alphabet
as always, while `base64wide` would use the custom alphabet.

### `xor` and `fullword` behave differently when used together

In YARA 4.x the combination `xor` and `fullword` looks for the bytes before
and after the XORed pattern and makes sure that they are not alphanumeric, so
the pattern `"mississippi" xor(1) fullword` matches `{lhrrhrrhqqh}`, which is the
result of XORing `mississippi` with 1. The pattern matches because the XORed
`mississippi` is delimited by the non-alphanumeric characters `{` and `}`.

In YARA-X the bytes before and after the pattern are also XORed before checking 
if they are alphanumeric, therefore `{lhrrhrrhqqh}` becomes `zmississippiz`,
which doesn't match `"mississippi" xor(1) fullword`. In other words, YARA-X 
searches for full words contained inside a longer XORed string, which is 
the intended behavior in most cases.

### Jump bounds in hex patterns can be written in hex, octal, etc

In YARA 4.x the following hex pattern is invalid:

`{ 01 02 03 [0x00-0x100] 04 05 06 }`

This is because the jump's upper and lower bounds can be expressed in base 10
only, `0x00` and `0x100` are not valid bounds. In YARA-X hex and octal values 
are accepted.

### Repetition quantifiers in regexps need an explicit minimum

In YARA 4.x this is a valid regexp `/ab{,2}c`, which is equivalent to `/ab{0,2}c`.
Most regular expression engines don't support this syntax, including the popular
ones PCRE and RE2, as far as I know only Python does it. YARA-X uses the 
`regex-syntax` crate for parsing regexps and therefore this is not supported.