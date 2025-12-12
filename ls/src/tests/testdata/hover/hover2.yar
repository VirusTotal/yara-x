rule one_line { strings: $a = "foo" condition: $a at 100 + 200 }

rule test {
  condition:
    one_line
}