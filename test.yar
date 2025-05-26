import "hash"

rule t { condition: hash.md5(0, filesize) == "AAB" }


rule x { condition: "AD" == hash.sha256(0,filesize) }
