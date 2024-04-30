---
title: "Python"
description: ""
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "python-api"
weight: 530
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Python is a popular language among YARA users. They use Python for all
kinds of automation tasks, and the YARA-X ecosystem wouldn't be complete
without the possibility of using it from Python programs.

YARA-X offers support for Python 3.8 or later, in Linux, MacOS and Windows.

## Installation

Installing the `yara-x` Python module couldn't be easier:

```shell
pip install yara-x
```

Afer the installation you can check if everything went fine by running
the following program:

```python
import yara_x

rules = yara_x.compile('''
  rule test { 
    strings: 
      $a = "foobar" 
    condition: 
      $a
  }''')

results = rules.scan(b"foobar")

assert results.matching_rules[0].identifier == "test"
assert results.matching_rules[0].patterns[0].identifier == "$a"
assert results.matching_rules[0].patterns[0].matches[0].offset == 0
assert results.matching_rules[0].patterns[0].matches[0].length == 6
```

If the program above runs without errors, everything is ready to start using
YARA-X from your Python programs.

## API reference