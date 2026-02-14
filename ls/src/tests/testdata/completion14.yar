import "pe"

rule with_for {
  condition:
    with
      version_info = pe.version_info,
      another = 10: (
        for any k, v in version_info: (
          k == "Key" and v == "Value" and a
        )
      )
}
