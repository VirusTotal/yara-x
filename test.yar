rule t {

  strings:
    $a = "foo"
    $b = "foo"
  condition: 
    all of them
}


