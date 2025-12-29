rule multiple_pattern {
  strings:
    $pattern_one = "pattern"
    $pattern_two = "pattern"
    $pattern_three = "pattern"
  condition:
    true
}