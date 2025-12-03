rule multiple_usages {
  condition:
    true
}

rule first_usage {
  condition:
    multiple_usages
}

rule second_usage {
  condition:
    multiple_usages
}