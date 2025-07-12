---
title: "Disabling warnings"
description: "Explains how to use comments for disabling warnings"
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "undefined"
weight: 300
toc: true
seo:
  title: "Disabling warnings"
  description: "Explains how to use comments for disabling warnings"
  noindex: false # false (default) or true
---

One of the key strengths of YARA-X is its improved feedback system. It provides 
more comprehensive and informative warnings during rule compilation, helping 
users catch issues early and write better rules. However, there are situations 
where not all warnings are helpful, especially when you're dealing with edge 
cases or legacy patterns.

You can disable specific kinds of warnings using the `--disable-warnings=<WARNING_ID>` 
command-line option, or through the configuration file. But these methods apply
globally, they affect the entire rule set, offering little flexibility when you
want to silence a specific warning in just one location.

Individual warnings at specific locations of your code can be disabled by using 
a comment of the form: `// suppress: <WARNING_ID>`.

This allows you to disable a warning only for a specific rule, pattern, or line, 
depending on the comment's position.

#### Examples

```
rule example_1
{
    condition:
        true // suppress: invariant_expr
}

rule example_2
{
    condition:
        // suppress: invariant_expr
        true 
}

// suppress: invariant_expr
rule example_2
{
    condition:
        true 
}
```

The effect of a `// suppress:` comment depends on where it appears in the code:

* Before a rule declaration: applies to the entire rule.

  ```
  // suppress: some_warning
  rule my_rule { ... }
  ```

* Before a pattern declaration: applies to the entire pattern.

  ```
  // suppress: text_as_hex
  $a = { 61 61 61 61 }
  ```

* At the end of a non-empty line: applies to the code that precedes it on the same line.


  ```
  condition: true // suppress: invariant_expr
  ```

* At the start of a line (on its own line): applies to the code on the line immediately following.

  ```
  condition: 
     // suppress: invariant_expr
     true 
  ```