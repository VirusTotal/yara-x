import "vt"
import "pe"
import "cuckoo"

rule test {
	condition:
		for any key, value in vt.metadata.signatures:
		(key == value)
		and
		for any value in pe.import_details[0].functions: (value.name == "test_name")
		and
		with
			a = pe.base_of_data,
			b = pe.checksum,
			c = cuckoo.network.dns_lookup(/foo/): (a == 1234)
}
