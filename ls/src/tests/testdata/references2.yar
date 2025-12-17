rule test_1 {
  strings:
    $pattern = "multiple pattern usages"
  condition:
    $pattern and #pattern in (0..20) and @pattern == 20
}