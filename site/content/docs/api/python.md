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

After the installation you can check if everything went fine by running
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

## API overview

Using YARA-X from Python involves a two-step process: rule compilation and
scanning. During the rule compilation phase you transform YARA rules from text
into a compiled [Rules](#rules) object. This object is later used for scanning
data.

To compiler rules, you can either use the [yara_x.compile(...)](#compile)
function or a [Compiler](#compiler) object. The former is simpler and sufficent
for simpler scenarios. For more complex use-cases involving the use of
namespaces and multiple rule sets, the latter method is necessary.

Once you have a [Rules](#rules) object, you can proceed in two ways: either use
the [Rules.scan(...)](#scanbytes) method, or create a [Scanner](#scanner).
Again, the former is the easiest way, but the later gives you more control over
the scanning process.

###### Examples

```python
# A very simple example
rules = yara_x.compile("rule test { condition: true }")
result = rules.scan(b"foo")
```

```python
# A more advanced example
compiler = yara_x.Compiler()
# Add more than one set of rules, each on a different namespace.
compiler.new_namespace("foo")
compiler.add_source("rule test { condition: true }")
compiler.new_namespace("bar")
compiler.add_source("rule test { condition: false }")
# Build the rules
rules = compiler.build()
# Pass the rules to a scanner, and set a scan timeout.
scanner = yara_x.Scanner(rules)
scanner.set_timeout(60)
# Scan some data.
result = scanner.scan(b"foo")
```

## API reference

### compile(...)

Function that takes a string with one or more YARA rules and produces
a [Rules](#rules) object representing the rules in compiled form. This is
the simplest way for compiling YARA rules, for more advanced use-cases you
must use a [Compiler](#compiler).

Returns: [yara_x.Rules](#rules)

Raises: #TODO

###### Example

```python
rules = yara_x.compile("rule test { condition: true }")
```

### Compiler

Type that represents a YARA-X compiler. It takes one or more sets of YARA
rules in text form and compile them into a [Rules](#rules) object.

#### .add_source(string)

Adds some YARA source code to be compiled. Raises an exception if the source
code is not valid.

Raises: #TODO

###### Example

```python
compiler = yara_x.Compiler()
compiler.add_source("rule test_1 { condition: true }")
compiler.add_source("rule test_2 { condition: false }")
rules = compiler.build()
```

#### .define_global(identifier, value)

Defines a global variable and sets its initial value.

Global variables must be defined before
calling [Compiler.add_source(...)](#add_sourcestring) with some YARA rule that
uses the variable. The variable will retain its initial value when
the [Rules](#rules) are used for scanning data, however each scanner can change
the variable's value by
calling [Scanner.set_global(...)](#set_globalidentifier-value).

The type of `value` must be: `bool`, `str`, `bytes`, `int` or `float`.

Raises: [TypeError](https://docs.python.org/3/library/exceptions.html#TypeError)
if the type of `value` is not one of the supported ones.

###### Example

```python
compiler = yara_x.Compiler()
compiler.define_global("my_int_var", 1) 
compiler.add_source("rule test { condition: my_int_var == 1 }")
```

#### .new_namespace(string)

Creates a new namespace. Any further call to `add_source` will put the new rules
under the new namespace, isolating them from previously added rules.

###### Example

```python
compiler = yara_x.Compiler()
compiler.new_namespace("foo")
# This "test" rule is under the "foo" namespace
compiler.add_source("rule test { condition: true }")
compiler.new_namespace("bar")
# This "test" rule is under the "bar" namespace. The rules 
# don't collide even if they are both named "test".
compiler.add_source("rule test { condition: false }")
rules = compiler.build()
```

#### .build()

Produces a compiled [Rules](#rules) object that contains all the rules
previously added to the compiler with `add_source`. Once this method is called
the Compiler is reset to its original state, as if it was a newly created
compiler.

### Rules

Type that represents a set of compiled rules. The compiled rules can be used for
scanning data by calling the [Rules.scan(...)](#scanbytes) method or passing
the [`Rules`](#rules)
object to a [Scanner](#scanner).

#### .scan(bytes)

Scans data with the compiled rules. This is the simplest way of using the
compiled rules for scanning data. For more advanced use-cases you can use
a [Scanner](#scanner).

Returns: [yara_x.ScanResults](#scanresults)

### Rule

Type that represents an individual YARA rule.

### Scanner

Type that represents a YARA-X scanner. When creating the Scanner you must
provide a [Rules](#rules) object containing the rules that will be used
during the scan operation. The same [Rules](#rules)  can be used by multiple
scanner simultaneously.

###### Example

```python
rules = yara_x.compile("rule test { condition: true }")
scanner = yara_x.Scanner(rules)
```

#### .scan(bytes)

Scans in-memory data.

Returns: [yara_x.ScanResults](#scanresults)

###### Example

```python
rules = yara_x.compile('rule foo { strings: $foo = "foo" condition: $foo }')
scanner = yara_x.Scanner(rules)
scanner.scan(b"foobar")
```

#### .scan_file(path)

Scans a file given its path.

Returns: [yara_x.ScanResults](#scanresults)

#### .set_global(identifier, value)

Sets the value of a global variable. The variable must has been previously
defined during the compilation, for example by calling
`Compiler.define_global`, and the type it has during the definition must match
the type of the new value. The variable will retain the new value in subsequent
scans, unless this function is called again for setting a new value.

#### .set_timeout(seconds)

Sets a timeout for each scan. Scans will abort after the specified `seconds`.

### ScanResults

Type that represents the results of a scan operation.

#### .matching_rules

Array of [Rule](#rule) objects with every rule that matched during the scan.

#### .module_outputs

#TODO