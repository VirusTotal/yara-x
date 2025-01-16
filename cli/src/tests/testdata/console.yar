import "console"
import "pe"

rule test {
  condition:
  	console.log("hello")
}