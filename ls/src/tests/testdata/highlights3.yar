rule test_1 {
  strings:
    $pattern = "foo"
  condition:
    $pattern
}