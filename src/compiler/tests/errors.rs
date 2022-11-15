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
  condition: 0
}
    "#,
            r#"error: wrong type
   ╭─[line:3:14]
   │
 3 │   condition: 0
   ·              ┬  
   ·              ╰── expression should be `boolean`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: not 2
}
    "#,
            r#"error: wrong type
   ╭─[line:3:18]
   │
 3 │   condition: not 2
   ·                  ┬  
   ·                  ╰── expression should be `boolean`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 2 and 3
}
    "#,
            r#"error: wrong type
   ╭─[line:3:14]
   │
 3 │   condition: 2 and 3
   ·              ┬  
   ·              ╰── expression should be `boolean`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: "foo" or "bar"
}
    "#,
            r#"error: wrong type
   ╭─[line:3:14]
   │
 3 │   condition: "foo" or "bar"
   ·              ──┬──  
   ·                ╰──── expression should be `boolean`, but is `string`
───╯
"#,
        ),
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
  condition: not 2+2
}
        "#,
            r#"error: wrong type
   ╭─[line:3:18]
   │
 3 │   condition: not 2+2
   ·                  ─┬─  
   ·                   ╰─── expression should be `boolean`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: true or "false"
}
        "#,
            r#"error: wrong type
   ╭─[line:3:22]
   │
 3 │   condition: true or "false"
   ·                      ───┬───  
   ·                         ╰───── expression should be `boolean`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 1 + "1"
}
           "#,
            r#"error: wrong type
   ╭─[line:3:18]
   │
 3 │   condition: 1 + "1"
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
  condition: 1 + -"1"
}
           "#,
            r#"error: wrong type
   ╭─[line:3:19]
   │
 3 │   condition: 1 + -"1"
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
  condition: !a[1]
}
"#,
            r#"error: wrong type
   ╭─[line:3:14]
   │
 3 │   condition: !a[1]
   ·              ──┬──  
   ·                ╰──── expression should be `boolean`, but is `integer`
───╯
"#,
        ),
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
        /*(
                    line!(),
                    r#"
        rule test {
          condition:
            for any n in (1, 2, 3) : (
              n == "3"
            )
        }
                "#,
                    r#""#,
                ),*/
    ];

    for t in tests {
        assert_eq!(
        Compiler::new().add_source(t.1)
            .expect_err(&*format!(
                "rule at line {} compiled without errors, but error was expected.\n\n",
                t.0,
            ))
            .to_string(),
        t.2,
        "test at line {}", t.0
    )
    }
}
