rule ident {
  condition:
    true
}

rule with_rule {
  condition:
    with
      ident = 10: (ident == 5 + 5)
}
