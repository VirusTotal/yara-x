use pretty_assertions::assert_eq;

use crate::compiler::Compiler;

#[rustfmt::skip]
#[test]
fn errors_1() {
    let tests = vec![
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
   condition: true
}

rule test {
   condition: false
}
"#,
            r#"error: duplicate rule `test`
   ╭─[line:2:6]
   │
 2 │ rule test {
   │      ──┬─  
   │        ╰─── `test` declared here for the first time
   │ 
 6 │ rule test {
   │      ──┬─  
   │        ╰─── duplicate declaration of `test`
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
   │              ──┬──    ┬  
   │                ╰───────── this expression is `string`
   │                       │  
   │                       ╰── this expression is `integer`
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
   │                  ─┬─  
   │                   ╰─── expression should be `float` or `integer`, but is `string`
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
   │              ─┬─  
   │               ╰─── expression should be `integer`, but is `float`
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
   │                   ─┬─  
   │                    ╰─── expression should be `float` or `integer`, but is `string`
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
   │                   ───┬───  
   │                      ╰───── expression should be `integer`, but is `float`
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
   │                   ─┬  
   │                    ╰── this number can not be negative
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
   │                             ┬  
   │                             ╰── expression should be `string`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: "foobar" matches "foobar"
}
"#,
            r#"error: wrong type
   ╭─[line:3:31]
   │
 3 │   condition: "foobar" matches "foobar"
   │                               ────┬───  
   │                                   ╰───── expression should be `regexp`, but is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: 1 matches /foobar/
}
"#,
            r#"error: wrong type
   ╭─[line:3:14]
   │
 3 │   condition: 1 matches /foobar/
   │              ┬  
   │              ╰── expression should be `string`, but is `integer`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition: "foobar" matches /foo[bar/
}
"#,
            r#"error: invalid regular expression
   ╭─[line:3:35]
   │
 3 │   condition: "foobar" matches /foo[bar/
   │                                   ┬  
   │                                   ╰── unclosed character class
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
   │               ──┬─  
   │                 ╰─── expression should be `integer`, but is `string`
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
    $a in (-1..0)
}
"#,
            r#"error: unexpected negative number
   ╭─[line:6:12]
   │
 6 │     $a in (-1..0)
   │            ─┬  
   │             ╰── this number can not be negative
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
    $a in (0..-2)
}
"#,
            r#"error: unexpected negative number
   ╭─[line:6:15]
   │
 6 │     $a in (0..-2)
   │               ─┬  
   │                ╰── this number can not be negative
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
    $a in (2..1)
}
"#,
            r#"error: invalid range
   ╭─[line:6:11]
   │
 6 │     $a in (2..1)
   │           ───┬──  
   │              ╰──── higher bound must be greater or equal than lower bound
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
    $a at "1"
}
"#,
            r#"error: wrong type
   ╭─[line:6:11]
   │
 6 │     $a at "1"
   │           ─┬─  
   │            ╰─── expression should be `integer`, but is `string`
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
    @a["1"] == 0x100
}
"#,
            r#"error: wrong type
   ╭─[line:6:8]
   │
 6 │     @a["1"] == 0x100
   │        ─┬─  
   │         ╰─── expression should be `integer`, but is `string`
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
    @a[0]
}
        "#,
            r#"error: number out of range
   ╭─[line:6:8]
   │
 6 │     @a[0]
   │        ┬  
   │        ╰── this number is out of the allowed range [1-9223372036854775807]
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
    !a[-1]
}"#,
            r#"error: number out of range
   ╭─[line:6:8]
   │
 6 │     !a[-1]
   │        ─┬  
   │         ╰── this number is out of the allowed range [1-9223372036854775807]
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
    #a in (0.."10")
}
        "#,
            r#"error: wrong type
   ╭─[line:6:15]
   │
 6 │     #a in (0.."10")
   │               ──┬─  
   │                 ╰─── expression should be `integer`, but is `string`
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
   │                     ─┬─  
   │                      ╰─── expression should be `integer`, but is `float`
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
   │                    ──┬─  
   │                      ╰─── expression should be `integer`, but is `string`
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
    $a at -1
}
"#,
            r#"error: unexpected negative number
   ╭─[line:6:11]
   │
 6 │     $a at -1
   │           ─┬  
   │            ╰── this number can not be negative
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
   │     ─┬─  
   │      ╰─── expression should be `integer`, but is `string`
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
   │     ─┬─  
   │      ╰─── this number is out of the allowed range [0-100]
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
   condition:
     for 3.14 x in (0..10) : (false)
}

"#,
            r#"error: wrong type
   ╭─[line:4:10]
   │
 4 │      for 3.14 x in (0..10) : (false)
   │          ──┬─  
   │            ╰─── expression should be `integer`, but is `float`
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
   │                 ┬  
   │                 ╰── expression should be `boolean`, but is `integer`
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
   │     ────────┬───────  
   │             ╰───────── this identifier has not been declared
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        #[cfg(feature = "test_proto2-module")]
        (
            line!(),
            r#"
rule test {
  condition:
    test_proto2.foo
}
        "#,
            r#"error: unknown identifier `test_proto2`
   ╭─[line:4:5]
   │
 4 │     test_proto2.foo
   │     ─────┬─────  
   │          ╰─────── this identifier has not been declared
   │ 
   │ Note: there is a module named `test_proto2`, but the `import "test_proto2"` statement is missing
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
   │ ──────┬─────  
   │       ╰─────── module `foo` not found
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
   │                    ┬  ─┬─  
   │                    ╰─────── this expression is `integer`
   │                        │   
   │                        ╰─── this expression is `string`
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
   │       ┬    ─┬─  
   │       ╰───────── this expression is `integer`
   │             │   
   │             ╰─── this expression is `string`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    for all x,y in (0..10) : ( true )
}
        "#,
            r#"error: assignment mismatch
   ╭─[line:4:13]
   │
 4 │     for all x,y in (0..10) : ( true )
   │             ─┬─    ───┬───  
   │              ╰────────────── this expects 2 value(s)
   │                       │     
   │                       ╰───── this produces 1 value(s)
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    for all x,y in (1, 2, 3) : ( true )
}
"#,
            r#"error: assignment mismatch
   ╭─[line:4:13]
   │
 4 │     for all x,y in (1, 2, 3) : ( true )
   │             ─┬─     ───┬───  
   │              ╰─────────────── this expects 2 value(s)
   │                        │     
   │                        ╰───── this produces 1 value(s)
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
   │       ┬  
   │       ╰── this identifier has not been declared
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
   │           ┬  
   │           ╰── this identifier has not been declared
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test_1 {
  condition:
    true
}

global rule test_2 {
  condition:
    test_1
}
"#,
            r#"error: global rule `test_2` depends on non-global rule `test_1`
   ╭─[line:9:5]
   │
 2 │ rule test_1 {
   │      ───┬──  
   │         ╰──── non-global rule `test_1` declared here
   │ 
 7 │ global rule test_2 {
   │             ───┬──  
   │                ╰──── global rule `test_2` declared here
   │ 
 9 │     test_1
   │     ───┬──  
   │        ╰──── `test_1` is used in the condition of `test_2`
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = /abc[xyz/
  condition:
    $a
}
"#,
            r#"error: invalid regular expression
   ╭─[line:4:14]
   │
 4 │     $a = /abc[xyz/
   │              ┬  
   │              ╰── unclosed character class
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = /abc.{-100}xyz/
  condition:
    $a
}
"#,
            r#"error: invalid regular expression
   ╭─[line:4:16]
   │
 4 │     $a = /abc.{-100}xyz/
   │                │ 
   │                ╰─ repetition quantifier expects a valid decimal
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = /abc[b-a]/
  condition:
    $a
}
"#,
            r#"error: invalid regular expression
   ╭─[line:4:15]
   │
 4 │     $a = /abc[b-a]/
   │               ─┬─  
   │                ╰─── invalid character class range, the start must be <= the end
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = /(abc/
  condition:
    $a
}
"#,
            r#"error: invalid regular expression
   ╭─[line:4:11]
   │
 4 │     $a = /(abc/
   │           ┬  
   │           ╰── unclosed group
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = /a[]b/
  condition:
    $a
}
"#,
            r#"error: invalid regular expression
   ╭─[line:4:12]
   │
 4 │     $a = /a[]b/
   │            ─┬  
   │             ╰── unclosed character class
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  strings:
    $a = /a.*b.*?c/
  condition:
    $a
}
"#,
            r#"error: mixing greedy and non-greedy quantifiers in regular expression
   ╭─[line:4:15]
   │
 4 │     $a = /a.*b.*?c/
   │            ─┬ ─┬─  
   │             ╰────── this is greedy
   │                │   
   │                ╰─── this is non-greedy
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    all of ($a*)
}
"#,
            r#"error: no matching patterns
   ╭─[line:4:13]
   │
 4 │     all of ($a*)
   │             ─┬─  
   │              ╰─── there's no pattern in this set
   │ 
   │ Note: `$a*` doesn't match any pattern identifier
───╯
"#,
        ),
        ////////////////////////////////////////////////////////////
        (
            line!(),
            r#"
rule test {
  condition:
    all of them
}
"#,
            r#"error: no matching patterns
   ╭─[line:4:12]
   │
 4 │     all of them
   │            ──┬─  
   │              ╰─── there's no pattern in this set
   │ 
   │ Note: this rule doesn't define any patterns
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
    for all x,y in test_proto2.array_int64 : ( true )
}
"#,
            r#"error: assignment mismatch
   ╭─[line:5:13]
   │
 5 │     for all x,y in test_proto2.array_int64 : ( true )
   │             ─┬─    ───────────┬───────────  
   │              ╰────────────────────────────── this expects 2 value(s)
   │                               │             
   │                               ╰───────────── this produces 1 value(s)
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
    for all x in test_proto2.map_string_int64 : ( true )
}
"#,
            r#"error: assignment mismatch
   ╭─[line:5:13]
   │
 5 │     for all x in test_proto2.map_string_int64 : ( true )
   │             ┬    ──────────────┬─────────────  
   │             ╰────────────────────────────────── this expects 1 value(s)
   │                                │               
   │                                ╰─────────────── this produces 2 value(s)
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
    for all x in test_proto2.int64_zero : ( true )
}
"#,
            r#"error: wrong type
   ╭─[line:5:18]
   │
 5 │     for all x in test_proto2.int64_zero : ( true )
   │                  ───────────┬──────────  
   │                             ╰──────────── expression should be `array` or `map`, but is `integer`
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
    for all k,v in test_proto2.map_int64_string : ( k == "1" )
}
"#,
            r#"error: mismatching types
   ╭─[line:5:53]
   │
 5 │     for all k,v in test_proto2.map_int64_string : ( k == "1" )
   │                                                     ┬    ─┬─  
   │                                                     ╰───────── this expression is `integer`
   │                                                           │   
   │                                                           ╰─── this expression is `string`
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
    for all k,v in test_proto2.map_int64_string : ( v == 1 )
}
"#,
            r#"error: mismatching types
   ╭─[line:5:53]
   │
 5 │     for all k,v in test_proto2.map_int64_string : ( v == 1 )
   │                                                     ┬    ┬  
   │                                                     ╰─────── this expression is `string`
   │                                                          │  
   │                                                          ╰── this expression is `integer`
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
    for all struct in test_proto2.array_struct : ( 
       struct.nested_int64_zero == "0" 
    )
}
"#,
            r#"error: mismatching types
   ╭─[line:6:8]
   │
 6 │        struct.nested_int64_zero == "0"
   │        ────────────┬───────────    ─┬─  
   │                    ╰──────────────────── this expression is `integer`
   │                                     │   
   │                                     ╰─── this expression is `string`
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
   │     ───────────┬──────────  
   │                ╰──────────── expression should be `array` or `map`, but is `integer`
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
   │                             ──┬──  
   │                               ╰──── expression should be `integer`, but is `string`
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
   │                                  ┬  
   │                                  ╰── expression should be `string`, but is `integer`
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
    test_proto2(1)
}
"#,
            r#"error: wrong type
   ╭─[line:5:5]
   │
 5 │     test_proto2(1)
   │     ─────┬─────  
   │          ╰─────── expression should be `function`, but is `struct`
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
   │                 ───┬───  
   │                    ╰───── this identifier has not been declared
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
    test_proto2.add(1, "2") == 3
}
"#,
            r#"error: wrong arguments
   ╭─[line:5:20]
   │
 5 │     test_proto2.add(1, "2") == 3
   │                    ────┬───  
   │                        ╰───── wrong arguments in this call
   │ 
   │ Note: accepted argument combinations:
   │
   │       (float, float)
   │       (integer, integer)
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
    test_proto2.head() == "foo"
}
"#,
            r#"error: wrong arguments
   ╭─[line:5:21]
   │
 5 │     test_proto2.head() == "foo"
   │                     ─┬  
   │                      ╰── wrong arguments in this call
   │ 
   │ Note: accepted argument combinations:
   │
   │       (integer)
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

#[test]
fn errors_2() {
    assert_eq!(
        Compiler::new()
            .define_global("foo", 1)
            .unwrap()
            .add_source("rule foo  {condition: true}")
            .unwrap_err()
            .to_string(),
        "error: rule `foo` conflicts with an existing identifier
   ╭─[line:1:6]
   │
 1 │ rule foo  {condition: true}
   │      ─┬─  
   │       ╰─── identifier already in use by a module or global variable
───╯
"
    );

    assert_eq!(
        Compiler::new()
            .add_source("rule foo : first {condition: true}")
            .unwrap()
            .add_source("rule foo : second {condition: true}")
            .unwrap_err()
            .to_string(),
        "error: duplicate rule `foo`
   ╭─[line:1:6]
   │
 1 │ rule foo : first {condition: true}
   │      ─┬─  
   │       ╰─── `foo` declared here for the first time
   │
   ├─[line:1:6]
   │
 1 │ rule foo : second {condition: true}
   │      ─┬─  
   │       ╰─── duplicate declaration of `foo`
───╯
"
    );
}
