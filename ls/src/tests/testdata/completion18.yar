rule test_pattern_ident {
  strings:
    $ = "anonymous"
    $my_str = "hello"
    $other = "world"
  condition:
    $
}
