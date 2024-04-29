This Python package allows using [YARA-X](https://virustotal.github.com/yara-x)
from your Python programs.

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