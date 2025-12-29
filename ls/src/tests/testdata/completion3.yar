rule pattern_length_propose {
  strings:
    $pattern_length = "pattern"
  condition:
    ! and true
}