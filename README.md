[![tests](https://github.com/VirusTotal/yara-x/actions/workflows/tests.yaml/badge.svg)](https://github.com/VirusTotal/yara-x/actions/workflows/tests.yaml)
[![coverage](https://codecov.io/gh/VirusTotal/yara-x/branch/main/graph/badge.svg?token=dPsruCiDqN)](https://app.codecov.io/gh/VirusTotal/yara-x)

## What's YARA-X?

YARA-X is completely new implementation of [YARA](https://github.com/VirusTotal/yara) in Rust. This project is
not production-ready yet, but it is mostly usable and evolving very quickly.
The ultimate goal of YARA-X is to serve as the future replacement for YARA.

## Changes with respect to YARA 4.x

This section describes the differences that YARA-X has with respect to YARA 4.x
so far. These differences are not set in stone yet and may change in the future.

### Negative numbers are not accepted in array indexing
  
The expression `@a[-1]` is valid in YARA 4.x, but its value is always
`undefined`. In YARA-X this is an error.

### Duplicate rule modifiers are not accepted

In YARA 4.x rules can have any number of `global` or `private`, for example the
following is valid:

```
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

### Stricter escaped characters in regular expressions

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
to match `\\x64\\Release\\create.pdb/`, but the missing "\" goes unnoticed and 
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
/To: [^<]*?<[^@]*?@[^>]*?.\gov[^>]*?>/
```

```
/[a-z,A-Z]:\\SAM\\clients\\Sam3\\enc\\SAM\obj\\Release\\samsam\.pdb/
```

YARA 4.4 introduces the `--strict-escape` argument that turn-on a strict 
check on escaped characters and return an error in such cases. This is also
the default behaviour in YARA-X.