---
title: "Global and private rules"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "global_and_private"
weight: 260
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

## Global rules

Global rules allow you to set restrictions that apply universally across all
your rules. For instance, if you want all rules to ignore files above a certain
size, instead of modifying each rule individually, you can create a global rule
like this:

```yara
global rule SizeLimit {
    condition:
        filesize < 2MB
}
```

You can define multiple global rules, which are evaluated before any other
rules. The rest of the rules are only evaluated if all global rules are
satisfied.

{{< callout title="Incompatibility warning">}}

YARA 4.x allows global rules to reference non-global rules, but in YARA-X a
global rule can depend only on other global rules.

{{< /callout >}}

## Private rules

Private rules are rules that YARA doesn't report when they match a file. While
rules that don't show up in reports might seem unproductive, they are valuable
when combined with YARA's ability to reference one rule from another (see
[referencing other rules]({{< ref "conditions.md" >}}#referencing-other-rules)
.). Private rules can act
as
foundational components for
other rules and keep YARA's output focused and
relevant. To declare a rule as private, simply add the keyword private before
the rule declaration.

```
private rule PrivateRuleExample{
    ...
}
```

You can apply both private and global modifiers to a rule, resulting in a global
rule that does not get reported by YARA but must be satisfied.