rule hover_config_rule {
  meta:
    author = "author"
  strings:
    $a = "foo"
  condition:
    for any i in (1..2) : (
      $a and i == 1
    )
}

rule caller {
  condition:
    hover_config_rule
}
