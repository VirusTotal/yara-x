---
title: "string"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "string-module"
weight: 900
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---


The `string` module implements string utility functions.

-------

## Functions

### to_int(string)

Converts the given string to a signed integer. If the string starts with "0x" it
is treated as base 16. If the string starts with "0" it is treated base 8.
Leading '+' or '-' is also supported.

Examples:

`string.to_int("1234") == 1234`

`string.to_int("-10") == -10`

`string.to_int("-010") == -8`

### to_int(string, base)

Converts the given string, interpreted with the given base, to a signed integer.
Base must be 0 or between 2 and 36 inclusive. If it is zero then the string will
be interpreted as base 16 if it starts with "0x" or as base 8 if it starts
with "0". Leading '+' or '-' is also supported.

Examples:

`string.to_int("011", 8) == 9`

`string.to_int("-011", 0) == -9`

### length(string)

Returns the length of the string, which can be any sequence of bytes. NULL bytes
included.

Examples:

`string.length("AXSx00ERS") == 7`

### index_of(string, needle)

Returns the byte offset of the first occurrence of `needle` in the string.
The result is undefined when `needle` is empty, when `needle` does not occur,
or when the offset does not fit in a signed 64-bit integer.

Examples:

`string.index_of("AXSERS", "ER") == 3`

`not defined string.index_of("AXSERS", "")`

### trim(string)

Returns the string with leading and trailing ASCII whitespace removed.
ASCII whitespace is space, horizontal tab, line feed, form feed, and
carriage return. The result is always defined. A string that is entirely
whitespace yields an empty string.

Examples:

`string.trim("  ab  ") == "ab"`

`string.trim(" \t") == ""`

### trim(string, cutset)

Returns the string with leading and trailing bytes removed when those bytes
appear in `cutset`. An empty `cutset` returns the string unchanged. The
result is always defined.

Examples:

`string.trim("\x00ab\x00", "\x00") == "ab"`

`string.trim(" ab ", "") == " ab "`

### reverse(string)

Returns the string with its bytes in reverse order. Bytes are reversed, not
Unicode scalar values.

Examples:

`string.reverse("abc") == "cba"`

`string.reverse("\xc3\xa9") == "\xa9\xc3"`

### replace(string, from, to)

Returns the string with every non-overlapping occurrence of `from` replaced
by `to`. The result is undefined when `from` is empty, or when the replaced
output would be larger than 1 MiB (1048576 bytes). When `from` does not
occur, the original string is returned.

Examples:

`string.replace("a.b.c", ".", "-") == "a-b-c"`

`not defined string.replace("abc", "", "x")`

`string.replace("abc", "z", "x") == "abc"`