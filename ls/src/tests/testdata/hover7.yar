rule test {
    strings:
        $ = "foo"
        $ = "bar"
    condition:
        all of them
}