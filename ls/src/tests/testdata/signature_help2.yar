import "pe"

rule test {
	condition:
		pe.delayed_import_rva("name", )
}
