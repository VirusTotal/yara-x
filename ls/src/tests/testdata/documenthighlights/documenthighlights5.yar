rule test_1 {
  strings:
    $pattern = "foo"
  condition:
    $pattern
}

rule test_2 {
  strings:
    $pattern = "foo"
  condition:
    $pattern
}