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
weight: 325
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---


The `string` module implements string utility functions.

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