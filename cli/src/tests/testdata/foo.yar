rule foo : bar baz {
  meta:
    string = "foo"
    bool = true
    int = 1
    float = 3.14
    regexp = "foo"
  strings:
    $foo = "foo"
    $foo_hex = { 66 6f 6f }
  condition:
    any of them
}
