import "pe"

rule test_for {
    condition:
        for any dir in pe.data_directories: (
            dir.
        )
}
