---
title: "Profiling your YARA rules"
description: "How to obtain information about the performance of your YARA rules"
summary: ""
date: 2024-11-26T00:00:00+01:00
lastmod: 2024-11-26T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Victor M. Alvarez" ]
pinned: false
homepage: false
seo:
  title: "Rules profiling" # custom title (optional)
  description: "Describes the new rules profiling feature introduced in YARA-X 0.11.0" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Not all YARA rules perform equally; some can significantly slow down scanning
throughput. When working with a large set of rules, identifying which ones are
causing performance bottlenecks can be challenging, especially without the right
tools.

To address this, YARA-X 0.11.0 introduces a new feature designed to streamline
the process of identifying slow rules: the `--profiling` option for
the `yr scan`
command.

## Enabling rules profiling

Because this feature incurs a slight performance overhead, it is disabled by
default. To use it, you must build YARA-X with profiling support enabled. This
can be done using the following command:

```shell
cargo build --release --features=rules-profiling
```

Once built with profiling support, you can activate the feature by adding the
`--profiling` flag to the scan command. For example:

```shell
yr scan --profiling my_rules.yar target_file
```

## How it works

When the `--profiling` option is used, the `scan` command will operate as usual
while also collecting performance data for your rules. After the scan is
complete,
the profiling results will be displayed, highlighting the slowest rules and
their execution times. A sample output is shown below:

```
«««««««««««« PROFILING INFORMATION »»»»»»»»»»»»

Slowest rules:

* rule                 : some_slow_rule
  namespace            : default
  pattern matching     : 21.433µs
  condition evaluation : 2.429054588s
  TOTAL                : 2.429076021s
  
* rule                 : another_slow-rule
  namespace            : default
  pattern matching     : 5.790941033s
  condition evaluation : 10.329µs
  TOTAL                : 5.790963123s
```

The profiling output lists the slowest-performing rules, ordered by total
execution time in descending order (the slowest rule appears first). Each
rule's performance is broken down into two components:

* Pattern matching time: The time spent searching for patterns specified in the
  rule.
* Condition evaluation time: The time spent evaluating the rule's conditions.

By reporting these metrics separately, the profiling feature helps you determine
whether a rule's slowness is due to inefficient pattern matching or complex
condition evaluation.

Rules with a total execution time below 100ms are excluded from the profiling
report to keep the output concise. If no rules meet the threshold, the profiling
section will remain empty, indicating that your rules are efficiently optimized.

This new feature empowers users to fine-tune their rule sets by identifying and
addressing performance bottlenecks with ease. I hope you find it useful.