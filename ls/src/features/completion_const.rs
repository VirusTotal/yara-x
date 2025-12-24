/*! This module contains constants used within code completion feature.

These constants are slices containing YARA-X keywords, that can appear in
various contexts. Arrays can additionally contain code snippets for
code completion suggestions.
 */

use yara_x_parser::cst::SyntaxKind;

pub(crate) const PATTERN_MODS: &[(SyntaxKind, &[&str])] = &[
    (
        SyntaxKind::STRING_LIT,
        &[
            "ascii",
            "wide",
            "nocase",
            "private",
            "fullword",
            "base64",
            "base64wide",
            "xor",
        ],
    ),
    (SyntaxKind::REGEXP, &["ascii", "wide", "nocase", "private", "fullword"]),
    (SyntaxKind::HEX_PATTERN, &["private"]),
];

pub const RULE_KW_BLKS: [&str; 3] = ["meta", "strings", "condition"];

pub const SRC_SUGGESTIONS: [(&str, Option<&str>); 5] = [
    ("rule", Some("rule ${1:ident} {\n\tcondition:\n\t\t${2:true}\n}")),
    ("import", Some("import \"${1:}\"")),
    ("include", Some("include \"${1:}\"")),
    ("private", None),
    ("global", None),
];

pub const CONDITION_SUGGESTIONS: [(&str, Option<&str>); 16] = [
    ("and", None),
    ("or", None),
    ("all", None),
    ("any", None),
    ("none", None),
    ("of", None),
    ("at", Some("at ${1:expression}")),
    ("in", Some("in ${1:}..${2:}")),
    ("filesize", None),
    ("entrypoint", None),
    ("true", None),
    ("false", None),
    ("not", None),
    ("defined", None),
    ("for", Some("for ${1:quantifier} ${2:iterable} : ( ${3:expression} )")),
    ("with", Some("with ${1:declarations} : ( ${3:expression} )")),
];
