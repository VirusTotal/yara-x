import "pe"

rule for_rule {
  condition:
    for any k, v in pe.version_info:
    (k == "key" and v == "value")
}
