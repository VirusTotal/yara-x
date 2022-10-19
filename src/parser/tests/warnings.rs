use crate::parser::Parser;
use pretty_assertions::assert_eq;

#[test]
fn syntax_errors() {
    let tests = vec![
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test { 
  strings: 
    $a = { 01 [1-2][3-4][1-3] 02 } 
  condition: 
    $a 
}"#,
            r#"warning: consecutive jumps in hex string `$a`
   ╭─[line:4:15]
   │
 4 │     $a = { 01 [1-2][3-4][1-3] 02 }
   ·               ───────┬───────  
   ·                      ╰───────── these consecutive jumps will be treated as [5-9]
───╯
"#,
        ),
        /*
                ////////////////////////////////////////////////////////////
                (
                    line!(),
                    r#"
        rule test {
          strings:
            $a = "foo"
            $b = "bar"
          condition:
            all of them at 0
        }"#,
                    r#"warning: potentially wrong expression
           ╭─[line:7:5]
           │
         7 │     all of them at 0
           ·     ─┬─         ──┬─
           ·      ╰──────────────── this implies that multiple patterns must match
           ·                   │
           ·                   ╰─── but all of them must match at the same offset
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
            $b = "bar"
          condition:
            all of ($*) at 0
        }"#,
                    r#"
        "#,
                ),

                 */
    ];

    for t in tests {
        let ast = Parser::new().build_ast(t.1, None).unwrap();
        assert!(!ast.warnings.is_empty());
        assert_eq!(ast.warnings[0].to_string(), t.2, "test at line {}", t.0)
    }
}
