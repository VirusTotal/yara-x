use custom_module_example::{Foobar, ensure_registered};

fn compile(src: &str) -> yara_x::Rules {
    ensure_registered();
    let mut c = yara_x::Compiler::new();
    c.add_source(src).expect("rules must compile");
    c.build()
}

fn matches(rules: &yara_x::Rules, data: &[u8]) -> Vec<String> {
    yara_x::Scanner::new(rules)
        .scan(data)
        .unwrap()
        .matching_rules()
        .map(|r| r.identifier().to_owned())
        .collect()
}

fn matches_with_output(
    rules: &yara_x::Rules,
    data: &[u8],
    output: Foobar,
) -> Vec<String> {
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_module_output(Box::new(output)).unwrap();
    scanner
        .scan(data)
        .unwrap()
        .matching_rules()
        .map(|r| r.identifier().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------

#[test]
fn module_is_in_registry() {
    ensure_registered();
    let names: Vec<&str> = yara_x::mods::module_names().collect();
    assert!(names.contains(&"foobar"), "foobar not in {names:?}");
}

#[test]
fn main_fn_populates_count_and_label() {
    let rules = compile(
        r#"
        import "foobar"
        rule count_matches  { condition: foobar.count == 4 }
        rule label_matches  { condition: foobar.label == "foobar" }
        "#,
    );
    let matched = matches(&rules, b"data");
    assert!(matched.contains(&"count_matches".to_owned()));
    assert!(matched.contains(&"label_matches".to_owned()));
}

#[test]
fn set_module_output_overrides_main_fn() {
    let rules = compile(
        r#"
        import "foobar"
        rule has_tag_alpha { condition: for any t in foobar.tags : (t == "alpha") }
        rule count_is_99    { condition: foobar.count == 99 }
        "#,
    );

    let mut output = Foobar::new();
    output.count = Some(99);
    output.label = Some("custom".to_owned());
    output.tags = vec!["alpha".to_owned(), "beta".to_owned()];

    let matched = matches_with_output(&rules, b"ignored", output);
    assert!(matched.contains(&"has_tag_alpha".to_owned()));
    assert!(matched.contains(&"count_is_99".to_owned()));
}

#[test]
fn compiled_rules_survive_serialize_deserialize() {
    let rules = compile(
        r#"
        import "foobar"
        rule label_check { condition: foobar.label == "persisted" }
        "#,
    );

    let blob = rules.serialize().expect("serialization must succeed");
    let rules = yara_x::Rules::deserialize(blob).expect("deserialization must succeed");

    let mut output = Foobar::new();
    output.label = Some("persisted".to_owned());

    let matched = matches_with_output(&rules, b"", output);
    assert_eq!(matched, vec!["label_check"]);
}

#[test]
fn module_fn_add_works() {
    let rules = compile(
        r#"
        import "foobar"
        rule add_works { condition: foobar.add(3, 4) == 7 }
        "#,
    );
    let matched = matches(&rules, b"data");
    assert!(matched.contains(&"add_works".to_owned()));
}

#[test]
fn no_tags_rule_does_not_match_when_tags_present() {
    let rules = compile(
        r#"
        import "foobar"
        rule no_tags { condition: foobar.count == 0 and not (for any t in foobar.tags : (true)) }
        "#,
    );

    let mut output = Foobar::new();
    output.count = Some(0);
    output.tags = vec!["something".to_owned()];

    let matched = matches_with_output(&rules, b"", output);
    assert!(matched.is_empty());
}
