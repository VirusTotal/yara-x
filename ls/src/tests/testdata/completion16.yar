import "pe"

rule test_with {
    condition:
        with foo = pe.data_directories[0]: (
            foo.
        )
}
