rule boolean_expr {
  strings:
    $foo = "foo"
    $bar = "bar"
  condition:
    $foo and $bar
}