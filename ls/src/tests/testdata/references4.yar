rule only_definition {
  condition:
    true
}

rule use_this_definition_first {
  condition:
    only_definition
}

rule use_this_definition_second {
  condition:
    only_definition
}