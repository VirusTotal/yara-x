rule test_1 {
  strings:
    $a = "foo" wide ascii nocase
  condition:
    $a
}