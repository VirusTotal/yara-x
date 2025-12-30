include "foo"

import "bar"
import ""

rule no_pattern {
  meta:
    description = "rule without patterns"
  condition:
    true
}

rule single_pattern {
  strings:
    $pattern = "pattern"
  condition:
    true
}

rule multiple_pattern {
  strings:
    $pattern_one = "pattern"
    $pattern_two = "pattern"
    $pattern_three = "pattern"
  condition:
    true
}