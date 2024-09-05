import "cuckoo"

rule udp_10_0_2_X {
	condition:
    cuckoo.network.udp(/10\.0\.2\.\d/, 53) and
    cuckoo.network.udp(/239\.255\.255\.\d/, 1900)
}

rule host_65_55_56_206 {
	condition:
		cuckoo.network.host(/65.55.56.206/)
}

rule shim_cache_mutex {
	condition:
		cuckoo.sync.mutex(/ShimCacheMutex/)
}

rule install_rdf {
  condition:
    cuckoo.filesystem.file_access(/.*install.rdf/)
}


rule lanman_server {
  condition:
    cuckoo.registry.key_access(/.*LanmanServer.*/)
}