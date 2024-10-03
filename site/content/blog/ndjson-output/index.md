---
title: "NDJSON output in YARA-X"
description: "How to process YARA-X output in JSON format"
summary: ""
date: 2024-08-16T00:00:00+01:00
lastmod: 2024-08-16T00:00:00+01:00
draft: false
weight: 50
categories: [ ]
tags: [ ]
contributors: [ "Victor M. Alvarez" ]
pinned: false
homepage: false
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Starting with version 0.6.0, YARA-X's command-line interface (CLI) now supports
NDJSON output —a feature contributed
by [Wesley Shields](https://github.com/wxsBSD), a seasoned contributor to YARA
who’s also been making strides in YARA-X. Welcome to the Rust world, Wes!

For those unfamiliar, NDJSON stands for "Newline Delimited JSON." It’s a text
format where each line is a standalone JSON object, making it ideal for easy
parsing.

The primary advantage of NDJSON is its simplicity in parsing. Whether you're
writing your own script or using popular tools
like [jq](https://jqlang.github.io/jq/), working with NDJSON is straightforward.
For example, you can scan a directory with YARA rules and output the results in
NDJSON format by running:

```shell
yr scan --output-format=ndjson <RULES_FILE> <DIRECTORY>
```

This command generates output like the following:

```text
{"path":"/home/test/mydir/foo.txt","rules":[{"identifier":"test_rule_1"}]}
{"path":"/home/test/mydir/bar.txt","rules":[{"identifier":"test_rule_2"}]}
{"path":"/home/test/mydir/baz.txt","rules":[{"identifier":"test_rule_3"}]}
```

Each line corresponds to a file that matches a YARA rule, with a JSON object
containing two fields: "path" and "rules." The "rules" field is an array of
objects detailing the rules that matched the specified file.

The `--output-format=ndjson` option can be combined with other options like
`--print-meta` (`-m`), `--print-tags` (`-g`), `--print-strings` (`-s`), and
`--print-namespace` (`-e`). These options allow you to include additional
information in the JSON objects. For instance:

```shell
yr scan --output-format=ndjson -m -g <RULES_FILE> <DIRECTORY>
```

This would produce output such as:

```text
{"path":"/home/test/mydir/foo.txt","rules":[{"namespace":"default","identifier":"test_rule_1","tags":["foo", "bar"]}]}
{"path":"/home/test/mydir/bar.txt","rules":[{"namespace":"default","identifier":"test_rule_2","tags":[]}]}
{"path":"/home/test/mydir/baz.txt","rules":[{"namespace":"default","identifier":"test_rule_3","tags":["foo"]}]}
```

Here, you’ll notice that the JSON objects now include additional information
about the rule’s namespace and tags, thanks to the `-m -g` options specified in
the command line.

## Leveraging jq with NDJSON output

The [jq](https://jqlang.github.io/jq/) tool is an excellent companion to
YARA-X's new NDJSON output feature. By combining the capabilities of YARA-X and
`jq`, you can achieve powerful data manipulation. Here are a few examples:

#### Extracting file paths

If you want to retrieve only the paths of files that match your YARA rules, you
can run:

```shell
yr scan --output-format=ndjson -m -g <RULES_FILE> <DIRECTORY> | jq .path
```

#### Listing rule names

If you want only the rule names:

```shell
yr scan --output-format=ndjson -m -g <RULES_FILE> <DIRECTORY> | jq '.rules[].identifier'
```

#### Filtering with Regular Expressions

Suppose you need to print the paths of files that match rules with names
following the pattern `my_rule_[0-9]+`. Here's how you can do it:

```shell
yr scan --output-format=ndjson -m -g <RULES_FILE> <DIRECTORY> | jq 'select(.rules[].identifier | test("my_rule_[0-9]+")) | .path'
```

#### Converting NDJSON to standard JSON

Another common use-case is converting the NDJSON output into standard JSON where
the result is an array where each item is a matching file:

```shell
yr scan --output-format=ndjson <RULES_FILE> <DIRECTORY> | jq -s .
```

The possibilities are endless. Once you master `jq`, you'll be able to perform
all sorts of sophisticated data manipulations. Enjoy!