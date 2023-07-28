use pretty_assertions::assert_eq;

use crate::compiler::Compiler;

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
   │               ───────┬───────  
   │                      ╰───────── these consecutive jumps will be treated as [5-9]
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test { 
  strings: 
    $a = { 0F 84 [4] [0-7] 8D } 
  condition: 
    $a 
}"#,
            r#"warning: consecutive jumps in hex pattern `$a`
   ╭─[line:4:18]
   │
 4 │     $a = { 0F 84 [4] [0-7] 8D }
   │                  ────┬────  
   │                      ╰────── these consecutive jumps will be treated as [4-11]
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
    all of them at 0
}"#,
            r#"warning: potentially wrong expression
   ╭─[line:7:5]
   │
 7 │     all of them at 0
   │     ─┬─         ──┬─  
   │      ╰──────────────── this implies that multiple patterns must match
   │                   │   
   │                   ╰─── but they must match at the same offset
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
            r#"warning: potentially wrong expression
   ╭─[line:7:5]
   │
 7 │     all of ($*) at 0
   │     ─┬─         ──┬─  
   │      ╰──────────────── this implies that multiple patterns must match
   │                   │   
   │                   ╰─── but they must match at the same offset
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
    2 of ($*) at 0
}"#,
            r#"warning: potentially wrong expression
   ╭─[line:7:5]
   │
 7 │     2 of ($*) at 0
   │     ┬         ──┬─  
   │     ╰─────────────── this implies that multiple patterns must match
   │                 │   
   │                 ╰─── but they must match at the same offset
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
    $c = "baz"
  condition:
    70% of ($*) at 0
}"#,
            r#"warning: potentially wrong expression
   ╭─[line:8:5]
   │
 8 │     70% of ($*) at 0
   │     ─┬          ──┬─  
   │      ╰──────────────── this implies that multiple patterns must match
   │                   │   
   │                   ╰─── but they must match at the same offset
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = /foo/i nocase
  condition: 
    $a
}
"#,
            r#"warning: redundant case-insensitive modifier
   ╭─[line:4:15]
   │
 4 │     $a = /foo/i nocase
   │               ┬ ───┬──  
   │               ╰───────── the `i` postfix indicates that the pattern is case-insensitive
   │                    │    
   │                    ╰──── the `nocase` modifier does the same
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
    3 of them
}"#,
            r#"warning: invariant boolean expression
   ╭─[line:7:5]
   │
 7 │     3 of them
   │     ─────┬────  
   │          ╰────── this expression is always false
   │ 
   │ Note: the expression requires 3 matching patterns out of 2
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        #[cfg(feature = "test_proto2-module")]
        (
            line!(),
            r#"
import "test_proto2"
import "test_proto2"
"#,
            r#"warning: duplicate import statement
   ╭─[line:3:1]
   │
 2 │ import "test_proto2"
   │ ──────────┬─────────  
   │           ╰─────────── `test_proto2` imported here for the first time
 3 │ import "test_proto2"
   │ ──────────┬─────────  
   │           ╰─────────── duplicate import
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 0
}
    "#,
            r#"warning: non-boolean expression used as boolean
   ╭─[line:3:14]
   │
 3 │   condition: 0
   │              ┬  
   │              ╰── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
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
            r#"warning: non-boolean expression used as boolean
   ╭─[line:3:14]
   │
 3 │   condition: 2 and 3
   │              ┬  
   │              ╰── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
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
            r#"warning: non-boolean expression used as boolean
   ╭─[line:3:14]
   │
 3 │   condition: "foo" or "bar"
   │              ──┬──  
   │                ╰──── this expression is `string` but is being used as `bool`
   │ 
   │ Note: non-empty strings are considered `true`, while the empty string ("") is `false`
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
            r#"warning: non-boolean expression used as boolean
   ╭─[line:3:22]
   │
 3 │   condition: true or "false"
   │                      ───┬───  
   │                         ╰───── this expression is `string` but is being used as `bool`
   │ 
   │ Note: non-empty strings are considered `true`, while the empty string ("") is `false`
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
            r#"warning: non-boolean expression used as boolean
   ╭─[line:3:18]
   │
 3 │   condition: not 2
   │                  ┬  
   │                  ╰── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
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
            r#"warning: non-boolean expression used as boolean
   ╭─[line:3:18]
   │
 3 │   condition: not 2+2
   │                  ─┬─  
   │                   ╰─── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
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
    !a[1]
}
"#,
            r#"warning: non-boolean expression used as boolean
   ╭─[line:6:5]
   │
 6 │     !a[1]
   │     ──┬──  
   │       ╰──── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
───╯
"#,
        ),
    ];

    for t in tests {
        let compiler = Compiler::new().add_source(t.1).unwrap();
        assert!(
            !compiler.warnings.is_empty(),
            "test at line {} didn't produce warnings",
            t.0
        );
        assert_eq!(
            compiler.warnings[0].to_string(),
            t.2,
            "test at line {}",
            t.0
        )
    }
}

#[test]
fn no_warnings() {
    let tests = vec![
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
    $b = "bar"
  condition:
    none of them at 0
}"#,
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
    0 of them at 0
}"#,
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
    any of them at 0
}"#,
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
    1 of them at 0
}"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
  condition:
    none of ($a*) at 0
}"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = "foo"
  condition:
    all of ($a*, $a*) at 0
}"#,
        ),
    ];

    for t in tests {
        let compiler = Compiler::new().add_source(t.1).unwrap();

        if !compiler.warnings.is_empty() {
            panic!(
                "test at line {} raised warning:\n{}",
                t.0, compiler.warnings[0]
            );
        }
    }
}
