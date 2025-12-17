rule multiline_condition {
  strings:
    $a = "bar"
    $b = {11 22}
  condition:
    $a
    and
    $b
}