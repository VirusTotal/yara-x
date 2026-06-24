    global private rule rich_syntax {
        meta:
            author = "test"
            version = 3.14
        strings:
            $a = "abc" ascii wide fullword
            $b = "cde" base64
            $c = { 01 02 [1-2] ?? }
            $d = /reg.*exp/i nocase
        condition:
            all of them and
            any of ($a*) and
            filesize > 100 and
            (1 << 2) + (8 >> 1) >= 4 and
            1 == 1 and
            2 != 3 and
            4 < 5 and
            6 <= 6 and
            7 > 2 and
            "foo" contains "f" and
            "bar" icontains "B" and
            "baz" startswith "b"
            and "qux" istartswith "Q" and
            "end" endswith "d" and
            "IEND" iendswith "D" and
            "eq" iequals "EQ" and
            "str" matches /str/ and
            not false and none of ($b*) and
            (1 & 2) | (3 ^ 4) != ~0 and
            5 % 2 == 1 and
            2 * 3 == 6 and
            1 - 1 == 0
    }
