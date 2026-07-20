// This test is working with the `ident` from `with`
rule ident {
  condition:
    true
}

rule with_the_same_ident {
  condition:
    ident and with
      ident = 10: (ident == 5 + 5)
}
