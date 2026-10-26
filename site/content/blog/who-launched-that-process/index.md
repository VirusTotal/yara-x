---
title: "Who launched that process?"
description: "The vt module now exposes the parent and the ancestors of every process seen in VirusTotal sandboxes, so Livehunt rules can follow process trees."
summary: ""
date: 2026-10-26T00:00:00+02:00
lastmod: 2026-10-26T00:00:00+02:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Jose Luis Sanchez Martinez" ]
pinned: false
homepage: false
seo:
  title: "Who launched that process?"
  description: "The vt module now exposes the parent and the ancestors of every process seen in VirusTotal sandboxes, so Livehunt rules can follow process trees."
  canonical: ""
  noindex: false
---

# Who launched that process?

The `vt` module is the VirusTotal-specific module that gives
[Livehunt](https://docs.virustotal.com/docs/livehunt) rules access to everything
VirusTotal knows about a file, including what happened when it ran in a sandbox.
One of the most useful parts of that data is the process tree: which processes
were created, and which process created each of them.

Getting that tree into YARA has always been a problem. A process tree is a
recursive structure, where each process has a list of children, and each child
has its own children. YARA-X modules are defined with Protocol Buffers, and
recursive messages are not supported: there is no way to iterate over a
structure of unknown depth. That is why `vt.behaviour.processes_tree` has never
been visible from YARA rules, and why rules had to rely on flat lists like
`vt.behaviour.processes_created`. A flat list tells you that `cmd.exe` and
`schtasks.exe` both ran, but not that one started the other.

## A flat list that remembers the parents

YARA-X v1.21.0 adds a `parent_name` field to the items in
`vt.behaviour.processes_list`, and v1.22.0 adds `ancestor_names`. VirusTotal now
fills that list for every sandbox report that includes a process tree, by
flattening it. The result is one entry per process, and each entry knows the
name of the process that created it and of the processes above it:

| Field | Description |
| :---- | :---- |
| `name` | The process name, usually including its command line. |
| `parent_name` | The `name` of the process that created this one. Empty for root processes and when the parent is unknown. |
| `ancestor_names` | The names of its ancestors, nearest first: `ancestor_names[0]` is the parent, `ancestor_names[1]` the grandparent, and so on. |
| `files_written`, `files_opened`, `files_deleted` | Files touched by this specific process. |

With that, asking "was `schtasks.exe /create` launched by `cmd.exe`?" becomes a
single loop:

## 

```yara
import "vt"

rule cmd_spawns_schtasks {
  condition:
    for any p in vt.behaviour.processes_list : (
      p.name icontains "schtasks" and
      p.name icontains "/create" and
      p.parent_name icontains "cmd.exe"
    )
}
```

## 

## Climbing the tree

`ancestor_names` holds the names of the ancestors of each process, nearest
first, so checking the grandparent is just a matter of indexing the array:

```yara
rule mshta_cmd_powershell {
  condition:
    for any ps in vt.behaviour.processes_list : (
      ps.name icontains "powershell" and
      ps.parent_name icontains "cmd.exe" and
      ps.ancestor_names[1] icontains "mshta.exe"
    )
}
```

This rule matches a PowerShell process started by `cmd.exe`, where that
`cmd.exe` was in turn started by `mshta.exe`. When the level does not matter,
loop over the array instead: `for any a in p.ancestor_names : (a icontains
"winword.exe")` is true when Word is anywhere among the ancestors of `p`.

## Combining parents and files

Since every entry also carries the files that process touched, the parent and
the file activity can be checked together. The next rule looks for a script host
running a script that was written by its own parent. To get to the parent's
entry, it searches the same list for the entry whose `name` is equal to the
child's `parent_name`, which is also how you can follow a long chain step by
step:

&nbsp;

```yara
import "vt"

rule parent_writes_script_child_runs_it {
  condition:
    for any child in vt.behaviour.processes_list : (
      (child.name icontains "wscript" or child.name icontains "cscript") and
       for any parent in vt.behaviour.processes_list : (
          parent.name == child.parent_name and
          for any f in parent.files_written : (
            (f iendswith ".vbs" or f iendswith ".vbe" or f iendswith ".js") and
            child.name icontains f
          )
       )
    )
}
```

Here `child.name icontains f` compares two strings that are only known at scan
time: the path written by the parent, and the command line of the child.
Operators like `icontains`, `iendswith` and `==` work with any string expression
on both sides, not only with literals. Notice also that the inner loops use
`child` and `parent`, the variables from the outer loops: YARA-X supports
nested loops that refer to outer variables, and they fit this kind of data very
naturally.

## A couple of tips

* **Use case-insensitive operators.** Each sandbox formats process names in its
  own way: some include the full path and command line, some only the executable
  name, and some leave environment variables like `%ComSpec%` unexpanded.
  `icontains` on the executable name is more robust than `==` or `startswith` on
  a full path.
* **Put the most selective conditions first.** YARA-X evaluates `and` with
  short-circuit semantics, so the inner loops only run for the entries that pass
  the conditions before them. In the last rule, the inner loops are only reached
  for the handful of processes that look like `wscript` or `cscript`, not for
  every process in the list.

`parent_name` and `ancestor_names` are available today in Livehunt, and in
Retrohunt for recently analyzed files. If you write rules on top of sandbox
data, give it a try and let us know what you think\!

&nbsp;