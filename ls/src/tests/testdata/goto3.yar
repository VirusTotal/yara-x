rule test_1 {
  strings:
    $a = "first_pattern"
  condition:
    $a
}

rule test_2 {
  strings:
    $a = "second_pattern"
  condition:
    $a
}