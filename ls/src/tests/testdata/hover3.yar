rule multiline_pattern {
	strings:
    $a = { 11 22
          33 44 }
  condition:
    $a
}