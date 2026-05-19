rule test_1 {
  strings:
    $pattern = "foo"
  condition:
    $pattern and @pattern and !pattern and #pattern
}