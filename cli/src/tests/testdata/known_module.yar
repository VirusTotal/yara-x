import "math"

rule test {
  condition:
     math.entropy(0, filesize) >= 0
}