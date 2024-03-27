---
title: "Anatomy of a rule"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "syntax"
weight: 210
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

YARA rules are easy to write and understand, and they have a syntax that
resembles the C programming language. Here is the simplest rule that you can
write for YARA, which does absolutely nothing:

```
rule example {
    condition:
        false
}
```

Each rule in YARA starts with the keyword `rule` followed by a rule identifier.
Rules are generally composed of two sections: pattern definitions and condition.
The pattern definition section is optional, and it can be omitted if the rule
doesn't rely on any patterns (as in the first example), but the condition
section is always required. The pattern definition section is where the patterns
that will be part of the rule are defined. Patterns can be defined as plain
text, raw bytes, or regular expressions, as shown in the following, more
realistic, example:

```yara
rule ExampleRule {
    strings:
        $text = "text here"
        $hex = { E2 34 A1 C8 23 FB }
        $regex = /some regular expression: \w+/
    condition:
        $text or $hex or $regex
}
```

You'll learn more about patterns in the [Patterns]({{< ref "patterns.md" >}})
section.

The condition section is where the logic of the rule resides. This section must
contain a boolean expression telling under which circumstances the data being
scanned satisfies the rule. Most of the time, the condition will refer to
previously defined patterns by using their identifiers. In this context the
pattern identifier acts as a boolean variable that will be true if the pattern
is found in the scanned data.