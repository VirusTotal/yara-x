rule test {
  strings:
    $a = "foo"
  condition:
    $a and $b
}