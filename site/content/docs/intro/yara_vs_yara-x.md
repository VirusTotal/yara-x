---
title: "YARA-X vs YARA"
description: "How YARA-X and YARA differ. Which are the pros and cons."
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "yara-x_vs_yara"
weight: 115
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

YARA-X intends to be the replacement for YARA, and it has been designed with
usability, backward-compatibility, and performance in mind. YARA-X is already
better than YARA in many aspects, but it's still very young and therefore some
features are not implemented yet, and there are rough edges that need to be
polished. This section covers the pros and cons of YARA-X versus YARA.

## The good things

Let's start by talking about the things that YARA-X does better. If you prefer
seeing the glass half-empty go to [the bad things](#the-bad-things) section.

### Better error reporting

Error reports in YARA-X are much more detailed and explicative. Each error
message tries to provide as much context about the error as possible, which
improves the user's experience. They also look better.

![duplicate_rule_error.png](duplicate_rule_error.png)

![wrong_arguments_error.png](wrong_arguments_error.png)

### More user friendly CLI

### Higher overall performance

### Parser reusability

## The bad things

Of course, not everything is great. YARA-X has some drawbacks that we need to
discuss too. Some of the drawbacks are related to the lack of features that
YARA already has, but YARA-X does not. These may be eliminated in the future as
YARA-X matures.

### API is not compatible

### No include statements

### No process scanning