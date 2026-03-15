rule demo_contains_abc {
  strings:
    $a = "abc"
  condition:
    $a
}
