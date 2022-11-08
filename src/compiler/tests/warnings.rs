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
   ·                   ╰─── but they must match at the same offset
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
   ·     ─┬─         ──┬─  
   ·      ╰──────────────── this implies that multiple patterns must match
   ·                   │   
   ·                   ╰─── but they must match at the same offset
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
   ·     ┬         ──┬─  
   ·     ╰─────────────── this implies that multiple patterns must match
   ·                 │   
   ·                 ╰─── but they must match at the same offset
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
   ·     ─┬          ──┬─  
   ·      ╰──────────────── this implies that multiple patterns must match
   ·                   │   
   ·                   ╰─── but they must match at the same offset
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
   ·     ─────┬────  
   ·          ╰────── this expression is always false
   · 
   · Note: the expression requires 3 matching patterns out of 2
───╯
"#,
        ),
    ];

    for t in tests {
        let compiler = Compiler::new().add_source(t.1).unwrap();
        assert!(!compiler.warnings.is_empty());
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
