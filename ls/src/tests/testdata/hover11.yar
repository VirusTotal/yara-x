import "pe"

rule test {
  condition:
    pe.is_pe
}
