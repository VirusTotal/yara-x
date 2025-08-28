---
title: "console"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "console-module"
weight: 100
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `console` module allows you to log information during condition execution.
By default, the log messages are sent to stdout.

Every function in the `console` module returns `true` for the purposes of
condition evaluation. This means you must logically `and` your statements
together to get the proper output. For example:

```yara
import "console"

rule example {
    condition:
        console.log("Hello") and console.log("World!")
}
```

-------

## Functions

### log(string)

Logs the given string.

Example: `console.log(pe.imphash())`

### log(message, string)

Logs the given message and string.

Example: `console.log("The imphash is: ", pe.imphash())`

### log(integer)

Logs the given integer.

Example: `console.log(uint32(0))`

### log(message, integer)

Logs the given message and integer.

Example: `console.log("32bits at 0: ", uint32(0))`

### log(float)

Logs the given float number.

Example: `console.log(math.entropy(0, filesize))`

### log(message, float)

Logs the given message and float number.

Example: `console.log("Entropy: ", math.entropy(0, filesize))`

### log(boolean)

Logs the given boolean value.

Example: `console.log(pe.is_32bit())`

### log(message, boolean)

Logs the given message and boolean value.

Example: `console.log("32 bit PE: ", pe.is_32bit())`

### hex(integer)

Logs the given number as hex.

Example: `console.hex(uint32(0))`

### hex(message, integer)

Logs the given message and number, with the number as hex.

Example: `console.hex("Hex at 0: ", uint32(0))`