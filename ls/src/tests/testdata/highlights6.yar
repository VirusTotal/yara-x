rule with_rule {
  condition:
    with
      a = 10,
      b = 11: (a == 10 and (a == b or b > 15))
}
