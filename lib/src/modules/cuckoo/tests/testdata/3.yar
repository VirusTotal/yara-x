import "cuckoo"

rule checkip {
	condition:
	  cuckoo.network.http_request(/.*/) == 0
}

rule checkip_get {
	condition:
	  not cuckoo.network.http_get(/.*/)
}

rule checkip_post {
	condition:
	  not cuckoo.network.http_post(/.*/)
}

rule checkip_dns {
	condition:
	  not cuckoo.network.dns_lookup(/.*/)
}

rule user_agent {
	condition:
	  not cuckoo.network.http_user_agent(/.*/)
}

rule mutex {
	condition:
	  not cuckoo.sync.mutex(/.*/)
}

rule file_access {
	condition:
	  not cuckoo.filesystem.file_access(/.*/)
}

rule reg {
	condition:
      cuckoo.registry.key_access(/.*/) == 0
}
