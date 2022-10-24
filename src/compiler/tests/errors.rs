use crate::compiler::Compiler;
use pretty_assertions::assert_eq;

#[test]
fn errors() {
    let tests = vec![
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
            r#"error: mismatching operator types
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
            r#"error: unexpected negative integer
   ╭─[line:3:19]
   │
 3 │   condition: 1 << -1 == 0
   ·                   ─┬  
   ·                    ╰── this number should not be negative
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
        /*(
                    line!(),
                    r#"
        rule test {
          condition: $a at "1"
        }
        "#,
                    r#"error: wrong expression type
          |
        3 |   condition: $a at "1"
          |                    ^^^ expression should be `integer`, but is `string`
          |"#,
                ),

                        ////////////////////////////////////////////////////////////
                        (
                            line!(),
                            r#"
                rule test {
                  condition: @a["1"] == 0x100
                }
                "#,
                            r#"error: wrong expression type
                  |
                3 |   condition: @a["1"] == 0x100
                  |                 ^^^ expression should be `integer`, but is `string`
                  |"#,
                        ),
                        ////////////////////////////////////////////////////////////
                        (
                            line!(),
                            r#"
                rule test {
                  condition: @a[1]
                }
                "#,
                            r#"error: wrong expression type
                  |
                3 |   condition: @a[1]
                  |              ^^^^^ expression should be `boolean`, but is `integer`
                  |"#,
                        ),
                        ////////////////////////////////////////////////////////////
                        (
                            line!(),
                            r#"
                rule test {
                  condition: !a[1]
                }
                "#,
                            r#"error: wrong expression type
                  |
                3 |   condition: !a[1]
                  |              ^^^^^ expression should be `boolean`, but is `integer`
                  |"#,
                        ),
                        ////////////////////////////////////////////////////////////
                        (
                            line!(),
                            r#"
                rule test {
                  condition: !a[-1]
                }
                "#,
                            r#"error: unexpected negative number
                  |
                3 |   condition: !a[-1]
                  |                 ^^ expression should be a non-negative integer
                  |"#,
                        ),
                        ////////////////////////////////////////////////////////////
                        (
                            line!(),
                            r#"
                rule test {
                  condition: #a in (0.."10")
                }
                "#,
                            r#"error: wrong expression type
                  |
                3 |   condition: #a in (0.."10")
                  |                        ^^^^ expression should be `integer`, but is `string`
                  |"#,
                        ),*/
    ];

    for t in tests {
        assert_eq!(
        Compiler::new().add(t.1)
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
