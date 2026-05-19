import "time"

rule test {
	condition:
		time.now()
}
