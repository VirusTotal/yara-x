rule foo {
  strings:
    $foo = "foo"
    $foo_hex = { 66 6f 6f }
  condition:
    any of them
}
