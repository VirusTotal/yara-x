rule test {
  strings:
    $a = "foo"
    $a = "bar"
  condition:
    $a
}