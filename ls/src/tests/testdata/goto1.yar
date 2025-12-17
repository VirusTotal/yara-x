rule test_1 {
  strings:
    $a = "foo"
  condition:
    $a at 100 + 200
}