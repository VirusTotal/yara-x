rule test_1 {
  strings:
    $pattern = "single pattern usage"
  condition:
    $pattern
}