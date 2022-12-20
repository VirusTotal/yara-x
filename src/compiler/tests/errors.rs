use pretty_assertions::assert_eq;

use crate::compiler::Compiler;

#[test]
fn errors() {
    let tests = vec![
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: "foo" == 2
}
    "#,
            r#"error: mismatching types
   ╭─[line:3:14]
   │
 3 │   condition: "foo" == 2
   ·              ──┬──    ┬  
   ·                ╰───────── this expression is `string`
   ·                       │  
   ·                       ╰── this expression is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 1 + "1" == 2
}
           "#,
            r#"error: wrong type
   ╭─[line:3:18]
   │
 3 │   condition: 1 + "1" == 2
   ·                  ─┬─  
   ·                   ╰─── expression should be `float` or `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 2.0 % 1 == 1
}
           "#,
            r#"error: wrong type
   ╭─[line:3:14]
   │
 3 │   condition: 2.0 % 1 == 1
   ·              ─┬─  
   ·               ╰─── expression should be `integer`, but is `float`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 1 + -"1" == 0
}
           "#,
            r#"error: wrong type
   ╭─[line:3:19]
   │
 3 │   condition: 1 + -"1" == 0
   ·                   ─┬─  
   ·                    ╰─── expression should be `float` or `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 1 << 2.0 + 2
}
"#,
            r#"error: wrong type
   ╭─[line:3:19]
   │
 3 │   condition: 1 << 2.0 + 2
   ·                   ───┬───  
   ·                      ╰───── expression should be `integer`, but is `float`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 1 << -1 == 0
}
"#,
            r#"error: unexpected negative number
   ╭─[line:3:19]
   │
 3 │   condition: 1 << -1 == 0
   ·                   ─┬  
   ·                    ╰── this number can not be negative
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: "111" contains 1
}
"#,
            r#"error: wrong type
   ╭─[line:3:29]
   │
 3 │   condition: "111" contains 1
   ·                             ┬  
   ·                             ╰── expression should be `string`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
  condition: 
    #a in (0.."10") == 0
}
"#,
            r#"error: wrong type
   ╭─[line:6:15]
   │
 6 │     #a in (0.."10") == 0
   ·               ──┬─  
   ·                 ╰─── expression should be `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: $a at "1"
}
"#,
            r#"error: wrong type
   ╭─[line:3:20]
   │
 3 │   condition: $a at "1"
   ·                    ─┬─  
   ·                     ╰─── expression should be `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: @a["1"] == 0x100
}
"#,
            r#"error: wrong type
   ╭─[line:3:17]
   │
 3 │   condition: @a["1"] == 0x100
   ·                 ─┬─  
   ·                  ╰─── expression should be `integer`, but is `string`
───╯
"#,
        ),
        /*
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
        rule test {
          condition: @a[1]
        }
        "#,
            r#""#,
        ),
        */
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: !a[-1]
}"#,
            r#"error: number out of range
   ╭─[line:3:17]
   │
 3 │   condition: !a[-1]
   ·                 ─┬  
   ·                  ╰── this number is out of the allowed range [1-9223372036854775807]
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: #a in (0.."10")
}
        "#,
            r#"error: wrong type
   ╭─[line:3:24]
   │
 3 │   condition: #a in (0.."10")
   ·                        ──┬─  
   ·                          ╰─── expression should be `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
  condition:
    any of them in (1.0..10)
}
        "#,
            r#"error: wrong type
   ╭─[line:6:21]
   │
 6 │     any of them in (1.0..10)
   ·                     ─┬─  
   ·                      ╰─── expression should be `integer`, but is `float`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
  condition:
    any of them at "10"
}
        "#,
            r#"error: wrong type
   ╭─[line:6:20]
   │
 6 │     any of them at "10"
   ·                    ──┬─  
   ·                      ╰─── expression should be `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
  condition:
    "1" of them
}
        "#,
            r#"error: wrong type
   ╭─[line:6:5]
   │
 6 │     "1" of them
   ·     ─┬─  
   ·      ╰─── expression should be `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
  condition:
    101% of them
}
        "#,
            r#"error: number out of range
   ╭─[line:6:5]
   │
 6 │     101% of them
   ·     ─┬─  
   ·      ╰─── this number is out of the allowed range [0-100]
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    1 of (true, 2, false)
}
        "#,
            r#"error: wrong type
   ╭─[line:4:17]
   │
 4 │     1 of (true, 2, false)
   ·                 ┬  
   ·                 ╰── expression should be `boolean`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    undeclared_ident
}
        "#,
            r#"error: unknown identifier `undeclared_ident`
   ╭─[line:4:5]
   │
 4 │     undeclared_ident
   ·     ────────┬───────  
   ·             ╰───────── this identifier has not been declared
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
import "foo""#,
            r#"error: unknown module `foo`
   ╭─[line:2:1]
   │
 2 │ import "foo"
   · ──────┬─────  
   ·       ╰─────── module `foo` not found
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    for 1 n in (1, 2, "3") : (
      n == 2
    )
}
        "#,
            r#"error: mismatching types
   ╭─[line:4:20]
   │
 4 │     for 1 n in (1, 2, "3") : (
   ·                    ┬  ─┬─  
   ·                    ╰─────── this expression is `integer`
   ·                        │   
   ·                        ╰─── this expression is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    for any n in (1, 2, 3) : (
      n == "3"
    )
}
"#,
            r#"error: mismatching types
   ╭─[line:5:7]
   │
 5 │       n == "3"
   ·       ┬    ─┬─  
   ·       ╰───────── this expression is `integer`
   ·             │   
   ·             ╰─── this expression is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    for any n in (1, 2, 3) : (
      x == "3"
    )
}
"#,
            r#"error: unknown identifier `x`
   ╭─[line:5:7]
   │
 5 │       x == "3"
   ·       ┬  
   ·       ╰── this identifier has not been declared
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    for any x in (1, 2, 3) : (
      for any y in (1, 2, 3) : (
         y == 1
      )
      and y == 1
    )
}
"#,
            r#"error: unknown identifier `y`
   ╭─[line:8:11]
   │
 8 │       and y == 1
   ·           ┬  
   ·           ╰── this identifier has not been declared
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        #[cfg(feature = "test_proto2-module")]
        (
            line!(),
            r#"
import "test_proto2"
rule test {
  condition:
    test_proto2.int64_zero[0]
}
"#,
            r#"error: wrong type
   ╭─[line:5:5]
   │
 5 │     test_proto2.int64_zero[0]
   ·     ───────────┬──────────  
   ·                ╰──────────── expression should be `array` or `map`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        #[cfg(feature = "test_proto2-module")]
        (
            line!(),
            r#"
import "test_proto2"
rule test {
  condition:
    test_proto2.array_int64["foo"]
}
"#,
            r#"error: wrong type
   ╭─[line:5:29]
   │
 5 │     test_proto2.array_int64["foo"]
   ·                             ──┬──  
   ·                               ╰──── expression should be `integer`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        #[cfg(feature = "test_proto2-module")]
        (
            line!(),
            r#"
import "test_proto2"
rule test {
  condition:
    test_proto2.map_string_int64[0]
}
"#,
            r#"error: wrong type
   ╭─[line:5:34]
   │
 5 │     test_proto2.map_string_int64[0]
   ·                                  ┬  
   ·                                  ╰── expression should be `string`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        #[cfg(feature = "test_proto2-module")]
        (
            line!(),
            r#"
import "test_proto2"
rule test {
  condition:
    test_proto2.ignored
}
"#,
            r#"error: unknown identifier `ignored`
   ╭─[line:5:17]
   │
 5 │     test_proto2.ignored
   ·                 ───┬───  
   ·                    ╰───── this identifier has not been declared
───╯
"#,
        ),
    ];

    for t in tests {
        assert_eq!(
        Compiler::new().add_source(t.1)
            .expect_err(&format!(
                "rule at line {} compiled without errors, but error was expected.\n\n",
                t.0,
            ))
            .to_string(),
        t.2,
        "test at line {}", t.0
    )
    }
}
