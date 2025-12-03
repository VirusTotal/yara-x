rule rule_identifier {
  strings:
    $pattern = "foo"
  condition:
    true
}

rule usage {
  condition:
    rule_identifier
}