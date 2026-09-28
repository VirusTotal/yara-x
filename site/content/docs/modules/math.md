---
title: "math"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2026-09-28T15:39:00-04:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "math-module"
weight: 700
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `math` module lets you calculate certain values from portions of your file and create signatures based on those results.

-------

## Functions

### entropy(offset, size)

Returns the entropy for `size` bytes starting at `offset`. `offset` is a file offset in bytes, or a virtual address when scanning a running process. `size` is the byte count from the start `offset`. The returned value is a float between 0.0 and 8.0.

Examples:

`math.entropy(0, filesize) >= 7` (checks the entropy of the entire file)

`math.entropy(512, 256) >= 7` (checks the 256 bytes starting at offset 512, e.g. bytes 512-767)

`math.entropy(0x7FFE1234A000, 4096) >= 7` (when scanning a running process, checks the 4096 bytes starting at virtual address `0x7FFE1234A000`)

### entropy(string)

Returns the entropy for the given string.

Examples:

`math.entropy("dummy") > 7`

#### Interpreting entropy

Both variants of `entropy` compute the [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of the byte sequence, using the standard formula `H = -sum(p(x) * log2(p(x)))`. Entropy is measured per byte (8 bits), so the result ranges from `0.0` to `8.0`:
* `0.0` means every byte in the range is identical
* `8.0` means all 256 byte values occur with equal frequency, which is the maximum possible randomness for a byte stream

Values above `7.0` are usually considered high entropy. Normal text, executable code, and most structured file formats have a fairly predictable byte distribution and typically score well below 7. Data that is compressed or encrypted has an almost uniform byte distribution because compression removes redundancy and encryption is designed to look indistinguishable from random data, so it tends to score close to 8.

Malware authors frequently pack or encrypt their payloads to evade signature-based detection and to hide strings/code from static analysis, so a high-entropy section is a common indicator of packing or encryption.

### monte_carlo_pi(offset, size)

Returns the percentage away from Pi for the `size` bytes starting at `offset` when run through the Monte Carlo from Pi test. `offset` is a file offset in bytes, or a virtual address when scanning a running process. The returned value is a float.

Examples:

`math.monte_carlo_pi(0, filesize) < 0.07`

### monte_carlo_pi(string)

Returns the percentage away from Pi for the given string.

### serial_correlation(offset, size)

Returns the [serial correlation](https://en.wikipedia.org/wiki/Autocorrelation) for the `size` bytes starting at `offset`. `offset` is a file offset in bytes, or a virtual address when scanning a running process. The returned value is a float between 0.0 and 1.0.

Examples:

`math.serial_correlation(0, filesize) < 0.2`

### serial_correlation(string)

Returns the [serial correlation](https://en.wikipedia.org/wiki/Autocorrelation) for the given string.

Examples:

`math.serial_correlation("BCA")` &rarr; `-0.5`

### mean(offset, size)

Returns the mean for the `size` bytes starting at `offset`. `offset` is a file offset in bytes, or a virtual address when scanning a running process. The returned value is a float.

Examples:

`math.mean(0, filesize) < 72.0`

### mean(string)

Returns the mean for the given string.

Examples:

`math.mean("ABCABC")` &rarr; `66.0`

### deviation(offset, size, mean)

Returns the deviation from the mean for the `size` bytes starting at `offset`. `offset` is a file offset in bytes, or a virtual address when scanning a running process. The returned value is a float.

The mean of an equally distributed random sample of bytes is 127.5, which is available as the constant `math.MEAN_BYTES`.

Examples:

`math.deviation(0, filesize, math.MEAN_BYTES) == 64.0`

### deviation(string, mean)

Returns the deviation from the mean for the given string.

### in_range(test, lower, upper)

Returns true if the test value is between lower and upper values. The
comparisons are inclusive.

Examples:

`math.in_range(math.deviation(0, filesize, math.MEAN_BYTES), 63.9, 64.1)`

### max(int, int)

Returns the maximum of two unsigned integer values.

### min(int, int)

Returns the minimum of two unsigned integer values.

### to_number(bool)

Returns 0 or 1. This is useful when writing a score-based rule.

Examples:

```
math.to_number(SubRule1) * 60 +
math.to_number(SubRule2) * 20 +
math.to_number(SubRule3) * 70 > 80
```

### abs(int)

Returns the absolute value of the signed integer.

Example: `math.abs(@a - @b) == 1`

### count(byte, offset, size)

Returns how often a specific byte occurs, starting at `offset` and looking at the next `size` bytes. `offset` is a file offset in bytes, or a virtual address when scanning a running process. `offset` and `size` are optional; if left empty, the complete file is searched.

Examples:

`math.count(0x4A) >= 10`

`math.count(0x00, 0, 4) < 2`

### percentage(byte, offset, size)

Returns the occurrence rate of a specific byte, starting at `offset` and looking at the next `size` bytes. `offset` is a file offset in bytes, or a virtual address when scanning a running process. The returned value is a float between 0 and 1. `offset` and `size` are optional; if left empty, the complete file is searched.

Examples:

`math.percentage(0xFF, filesize-1024, filesize) >= 0.9`

`math.percentage(0x4A) >= 0.4`

### mode(offset, size)

Returns the most common byte, starting at `offset` and looking at the next `size` bytes. `offset` is a file offset in bytes, or a virtual address when scanning a running process. The returned value is a float. `offset` and `size` are optional; if left empty, the complete file is searched.

Examples:

`math.mode(0, filesize) == 0xFF`

`math.mode() == 0x00`

### to_string(int)

Converts the given integer to a string. Note: integers in YARA are signed.

Examples:

`math.to_string(10) == "10"`

`math.to_string(-1) == "-1"`

### to_string(int, base)

Converts the given integer to a string in the given base. Supported bases are 10, 8, and 16. Note: integers in YARA are signed.

Examples:

`math.to_string(32, 16) == "20"`

`math.to_string(-1, 16) == "ffffffffffffffff"`
