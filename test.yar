rule t {
  strings:
    $pdb2 = /RSDS\Release\RllSourc{00-}e\.pdb\x00/
  condition:
   all of them

}
