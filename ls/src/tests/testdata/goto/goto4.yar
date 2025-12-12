rule test_1 {
  strings:
    $a = "foo"
  condition:
    $a and @a == 10
}