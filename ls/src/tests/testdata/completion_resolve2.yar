rule resolve_example_rule {
  meta:
    author = "author"
    description = "description"
  strings:
    $a = "foo"
    $b = { 01 02 }
  condition:
    $a and $b
}
