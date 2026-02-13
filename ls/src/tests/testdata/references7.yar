import "pe"

rule with_for {
  condition:
    with
      v = pe.version_info: (
        for any k, v in v:
        (k == "key" and v == "value")
      )
}
