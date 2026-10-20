rule test_with {
    condition:
        with section = elf.sections[0]: (
            section.
        )
}
