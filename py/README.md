![PyPI - Version](https://img.shields.io/pypi/v/yara-x)
![PyPI - License](https://img.shields.io/pypi/l/yara-x)
[![Documentation](https://img.shields.io/badge/doc-latest-blue.svg)](https://virustotal.github.io/yara-x/docs/api/python)
[![Downloads](https://pepy.tech/badge/yara-x)](https://pepy.tech/project/yara-x)
[![Downloads per week](https://pepy.tech/badge/yara-x/week)](https://pepy.tech/project/yara-x)
![GitHub Repo stars](https://img.shields.io/github/stars/VirusTotal/yara-x)

The official Python library for [YARA-X](https://virustotal.github.io/yara-x).
Supports Python 3.8+ in Linux, MacOS and Windows.

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

For more information about how to use this library, please check
the [documentation](https://virustotal.github.io/yara-x/docs/api/python).