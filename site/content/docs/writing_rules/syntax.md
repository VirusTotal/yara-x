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

The condition section is where the logic of the rule resides. This section must
contain a boolean expression telling under which circumstances the data being
scanned satisfies the rule. Most of the time, the condition will refer to
previously defined patterns by using their identifiers. In this context the
pattern identifier acts as a boolean variable that will be true if the pattern
is found in the scanned data.

You will learn more about how to write rule conditions in the [Conditions]({{<
ref "conditions.md" >}}) section.

## Metadata

Besides the pattern definition and condition sections, rules can also have a
metadata section where you can put additional information about your rule. The
metadata section is defined with the keyword `meta` and contains
identifier/value pairs like in the following example:

```yara
rule MetadataExample {
    meta:
        my_identifier_1 = "Some string data"
        my_identifier_2 = 24
        my_identifier_3 = true
    strings:
        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }
    condition:
        $my_text_string or $my_hex_string
}
```

As shown in the example, metadata identifiers are followed by an equal sign and
the value assigned to them. Values can be strings (valid UTF8 only), integers,
or one of the boolean values `true` or `false`.

Note that identifier/value pairs defined in the metadata section cannot be used
in the condition section, their only purpose is to store additional information
about the rule.

## Comments

You can add comments to your YARA rules just as if it was a C source file, both
single-line and multi-line C-style comments are supported.

```yara
/*
This is a multi-line comment ...
*/

rule CommentExample // ... and this is single-line comment
{
    condition:
        false // just a dummy rule, don't do this
}
```