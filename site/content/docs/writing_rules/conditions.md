---
title: "Conditions"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "conditions"
weight: 230
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---


Conditions are nothing more than boolean expressions as those that can be found
in all programming languages, for example in an if statement. They can contain
the typical Boolean operators and, or, and not, and relational
operators >=, <=, <, >, == and !=. Also, the arithmetic
operators (+, -, *, \, %) and bitwise operators (&, |, <<, >>, ~, ^) can be used
on numerical expressions.

Integers are always 64-bits long, even the results of functions like uint8,
uint16 and uint32 are promoted to 64-bits. This is something you must take into
account, specially while using bitwise operators (for example, ~0x01 is not 0xFE
but 0xFFFFFFFFFFFFFFFE).

The following table lists the precedence and associativity of all operators. The
table is sorted in descending precedence order, which means that operators
listed on a higher row in the list are grouped prior operators listed in rows
further below it. Operators within the same row have the same precedence, if
they appear together in a expression the associativity determines how they are
grouped.