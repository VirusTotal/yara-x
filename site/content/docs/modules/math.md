---
title: "math"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
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

The `math` module allows you to calculate certain values from portions of your
file and create signatures based on those results.

-------

## Functions

### entropy(offset, size)

Returns the entropy for size bytes starting at offset. When scanning a running
process the offset argument should be a virtual address within the process
address space. The returned value is a float.

Examples:

`math.entropy(0, filesize) >= 7`

### entropy(string)

Returns the entropy for the given string.

Examples:

`math.entropy("dummy") > 7`

### monte_carlo_pi(offset, size)

Returns the percentage away from Pi for the size bytes starting at offset when
run through the Monte Carlo from Pi test. When scanning a running process the
offset argument should be a virtual address within the process address space.
The returned value is a float.

Examples:

`math.monte_carlo_pi(0, filesize) < 0.07`

### monte_carlo_pi(string)

Returns the percentage away from Pi for the given string.

### serial_correlation(offset, size)

Returns the serial correlation for the size bytes starting at offset. When
scanning a running process the offset argument should be a virtual address
within the process address space. The returned value is a float between 0.0 and
1.0.

Examples:

`math.serial_correlation(0, filesize) < 0.2`

### serial_correlation(string)

Returns the serial correlation for the given string.

### mean(offset, size)

Returns the mean for the size bytes starting at offset. When scanning a running
process the offset argument should be a virtual address within the process
address space. The returned value is a float.

Examples:

`math.mean(0, filesize) < 72.0`

### mean(string)

Returns the mean for the given string.

### deviation(offset, size, mean)

Returns the deviation from the mean for the size bytes starting at offset. When
scanning a running process the offset argument should be a virtual address
within the process address space. The returned value is a float.

The mean of an equally distributed random sample of bytes is 127.5, which is
available as the constant `math.MEAN_BYTES`.

Examples:

`math.deviation(0, filesize, math.MEAN_BYTES) == 64.0`

### deviation(string, mean)

Returns the deviation from the mean for the given string.

### in_range(test, lower, upper)

Returns true if the test value is between lower and upper values. The
comparisons are inclusive.

Examples:

`math.in_range(math.deviation(0, filesize, math.MEAN_BYTES), 63.9, 64,1)`

### max(int, int)

Returns the maximum of two unsigned integer values.

### min(int, int)

Returns the minimum of two unsigned integer values.

### to_number(bool)

Returns 0 or 1, it's useful when writing a score based rule.

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

Returns how often a specific byte occurs, starting at offset and looking at the
next size bytes. When scanning a running process the offset argument should be a
virtual address within the process address space. offset and size are optional;
if left empty, the complete file is searched.

Examples:

`math.count(0x4A) >= 10`

`math.count(0x00, 0, 4) < 2`

### percentage(byte, offset, size)

Returns the occurrence rate of a specific byte, starting at offset and looking
at the next size bytes. When scanning a running process the offset argument
should be a virtual address within the process address space. The returned value
is a float between 0 and 1. offset and size are optional; if left empty, the
complete file is searched.

Examples:

`math.percentage(0xFF, filesize-1024, filesize) >= 0.9`

`math.percentage(0x4A) >= 0.4`

### mode(offset, size)

Returns the most common byte, starting at offset and looking at the next size
bytes. When scanning a running process the offset argument should be a virtual
address within the process address space. The returned value is a float. offset
and size are optional; if left empty, the complete file is searched.

Examples:

`math.mode(0, filesize) == 0xFF`

`math.mode() == 0x00`

### to_string(int)

Converts the given integer to a string. Note: integers in YARA are signed.

Examples:

`math.to_string(10) == "10" Example: math.to_string(-1) == "-1"`

### to_string(int, base)

Converts the given integer to a string in the given base. Supported bases are
10,
8 and 16. Note: integers in YARA are signed.

Examples:

`math.to_string(32, 16) == "20"`

`math.to_string(-1, 16) == "ffffffffffffffff"`