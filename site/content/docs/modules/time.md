---
title: "time"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "time-module"
weight: 325
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `time` module implements time utility functions.

## Functions

### now()

Returns the current time as a Unix timestamp (number of seconds since January 1,
1970).

Example: `pe.timestamp > time.now()`