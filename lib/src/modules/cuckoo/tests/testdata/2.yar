import "cuckoo"

rule checkip {
	condition:
	  cuckoo.network.http_request(/.*checkip.*/)
}

rule checkip_get {
	condition:
	  cuckoo.network.http_get(/.*checkip.*/)
}

rule checkip_post {
	condition:
	  cuckoo.network.http_post(/.*checkip.*/)
}

rule checkip_dns {
	condition:
	  cuckoo.network.dns_lookup(/.*checkip.*/)
}

rule indy_user_agent {
	condition:
	  cuckoo.network.http_user_agent(/.*Indy Library.*/)
}


