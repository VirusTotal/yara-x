use pretty_assertions::assert_eq;

use crate::parser::Parser;

#[test]
fn warnings() {
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
            r#"warning: consecutive jumps in hex pattern `$a`
   ╭─[line:4:15]
   │
 4 │     $a = { 01 [1-2][3-4][1-3] 02 }
   ·               ───────┬───────  
   ·                      ╰───────── these consecutive jumps will be treated as [5-9]
───╯
"#,
        ),
    ];

    for t in tests {
        let ast = Parser::new().build_ast(t.1).unwrap();
        assert!(!ast.warnings.is_empty());
        assert_eq!(ast.warnings[0].to_string(), t.2, "test at line {}", t.0)
    }
}
