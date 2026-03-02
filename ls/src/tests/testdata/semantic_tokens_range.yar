rule range_test {
    strings:
        $a = "foo"
        $b = "bar"
    condition:
        $a and $b
}
