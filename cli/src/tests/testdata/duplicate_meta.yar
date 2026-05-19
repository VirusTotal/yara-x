rule duplicate_meta {
  meta:
    author = "Test Author"
    hash = "aaa111"
    hash = "bbb222"
    hash = "ccc333"
    description = "Rule with duplicate metadata keys"
  condition:
    true
}
