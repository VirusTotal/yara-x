rule test {
	strings:
          $a = "foobar"
        condition:
          $a
}
