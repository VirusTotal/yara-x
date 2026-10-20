rule test_for {
    condition:
        for any section in elf.sections: (
            section.
        )
}
