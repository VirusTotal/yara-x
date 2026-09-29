rule test_meta {
  meta:
    description = 123
    id = "bug123"
    version = "one"
    score = 10
    enabled = "yes"
    created = "03-07-2026"
    updated = "2026-07-03"
  condition:
    filesize > 0
}
