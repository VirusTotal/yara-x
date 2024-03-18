use pretty_assertions::assert_eq;
use std::iter::zip;

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
    $a = { 01 02 [1-2][3-4][1-3] 03 04 } 
  condition: 
    $a 
}"#,
            vec![
                r#"warning: consecutive jumps in hex pattern `$a`
   ╭─[line:4:18]
   │
 4 │     $a = { 01 02 [1-2][3-4][1-3] 03 04 }
   │                  ───────┬───────  
   │                         ╰───────── these consecutive jumps will be treated as [5-9]
───╯
"#,
            ],
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
            vec![
                r#"warning: consecutive jumps in hex pattern `$a`
   ╭─[line:4:18]
   │
 4 │     $a = { 0F 84 [4] [0-7] 8D }
   │                  ────┬────  
   │                      ╰────── these consecutive jumps will be treated as [4-11]
───╯
"#,
            ],
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
            vec![
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
            ],
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
            vec![
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
            ],
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
            vec![
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
            ],
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
            vec![
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
            ],
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
            vec![
                r#"warning: redundant case-insensitive modifier
   ╭─[line:4:15]
   │
 4 │     $a = /foo/i nocase
   │               ┬ ───┬──  
   │               ╰───────── the `i` suffix indicates that the pattern is case-insensitive
   │                    │    
   │                    ╰──── the `nocase` modifier does the same
───╯
"#,
            ],
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
            vec![
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
            ],
        ),
        ////////////////////////////////////////////////////////////
        #[cfg(feature = "test_proto2-module")]
        (
            line!(),
            r#"
import "test_proto2"
import "test_proto2"
"#,
            vec![
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
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 0
}
    "#,
            vec![
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
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: for any i in (0..1): ( 1 )
}
    "#,
            vec![
                r#"warning: non-boolean expression used as boolean
   ╭─[line:3:37]
   │
 3 │   condition: for any i in (0..1): ( 1 )
   │                                     ┬  
   │                                     ╰── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
───╯
"#,
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings: 
    $a = "foo"
  condition: 
    for any of them: ( 1 )
}
    "#,
            vec![
                r#"warning: non-boolean expression used as boolean
   ╭─[line:6:24]
   │
 6 │     for any of them: ( 1 )
   │                        ┬  
   │                        ╰── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
───╯
"#,
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 2 and 3
}
    "#,
            vec![
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
            "warning: non-boolean expression used as boolean
   ╭─[line:3:20]
   │
 3 │   condition: 2 and 3
   │                    ┬  
   │                    ╰── this expression is `integer` but is being used as `bool`
   │ 
   │ Note: non-zero integers are considered `true`, while zero is `false`
───╯
"],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: "foo" or true
}
    "#,
            vec![
                r#"warning: non-boolean expression used as boolean
   ╭─[line:3:14]
   │
 3 │   condition: "foo" or true
   │              ──┬──  
   │                ╰──── this expression is `string` but is being used as `bool`
   │ 
   │ Note: non-empty strings are considered `true`, while the empty string ("") is `false`
───╯
"#,
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: true or "false"
}
        "#,
            vec![
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
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: not 2
}
    "#,
            vec![
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
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: not 2+2
}
        "#,
            vec![
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
            ],
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
            vec![
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
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = {00 [1-10] 01}
  condition: 
    $a
}
"#,
            vec![
                r#"warning: slow pattern
   ╭─[line:4:10]
   │
 4 │     $a = {00 [1-10] 01}
   │          ───────┬──────  
   │                 ╰──────── this pattern may slow down the scan
───╯
"#,
            ],
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
import "unsupported_module"
rule test_1 {
  condition: 
    unsupported_module.foo()
}

rule test_2 {
  condition: 
    test_1
}

"#,
            vec![
                r#"warning: module `unsupported_module` is not supported
   ╭─[line:2:1]
   │
 2 │ import "unsupported_module"
   │ ─────────────┬─────────────  
   │              ╰─────────────── module `unsupported_module` used here
───╯
"#,
                "warning: module `unsupported_module` is not supported
   ╭─[line:5:5]
   │
 5 │     unsupported_module.foo()
   │     ─────────┬────────  
   │              ╰────────── module `unsupported_module` used here
   │ 
   │ Note: the whole rule `test_1` will be ignored
───╯
",
            "warning: rule `test_2` will be ignored due to an indirect dependency on module `unsupported_module`
    ╭─[line:10:5]
    │
 10 │     test_1
    │     ───┬──  
    │        ╰──── this other rule depends on module `unsupported_module`, which is unsupported
────╯
",],
        ),
    ];

    for t in tests {
        let mut compiler = Compiler::new();
        compiler
            .add_unsupported_module("unsupported_module")
            .add_source(t.1)
            .unwrap();
        assert!(
            !compiler.warnings.is_empty(),
            "test at line {} didn't produce warnings",
            t.0
        );
        for (warning, expected) in zip(&compiler.warnings, &t.2) {
            assert_eq!(warning.to_string(), *expected, "test at line {}", t.0)
        }
        assert_eq!(
            compiler.warnings.len(),
            t.2.len(),
            "expecting {} warnings, got {} in test at line {}",
            t.2.len(),
            compiler.warnings.len(),
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
        let mut compiler = Compiler::new();
        compiler.add_source(t.1).unwrap();
        if !compiler.warnings.is_empty() {
            panic!(
                "test at line {} raised warning:\n{}",
                t.0, compiler.warnings[0]
            );
        }
    }
}
