rule rule_identifier {
  strings:
    $pattern = "foo"
  condition:
    true
}

rule first_usage {
  condition:
    rule_identifier
}

rule second_usage {
  condition:
    rule_identifier
}

rule third_usage {
  condition:
    rule_identifier
}