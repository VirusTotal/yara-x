rule patterns {
  meta:
    author = "unknown"
    description = "some description"
  strings:
    $regex1 = /md5: [0-9a-fA-F]{32}/
    $regex2 = /bar./s
    $hex = { E2 34 ?? C8 A? FB }
    $wide = "wide" wide
    $nocase = "nocase" nocase
    $wide_and_ascii = "wide and ascii" wide ascii
    $xor = "xor" xor
    $base = "base64" base64
  condition:
    $regex1 and $regex2 and $hex and $wide and $nocase and $wide_and_ascii and $xor and $base
}

rule use_patterns { condition: patterns }