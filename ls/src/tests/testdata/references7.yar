import "pe"

rule with_the_same_ident {
  condition:
    with
      v = pe.version_info: (
        for any k, v in v:
        (k == "key" and v == "value")
      )
}
