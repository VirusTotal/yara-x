use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

use crate::tests::rule_true;
use crate::tests::test_rule;

/// Creates a minimal VSIX file with the given package.json content.
fn create_vsix(package_json: &str) -> Vec<u8> {
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default();

        // Add extension/package.json
        zip.start_file("extension/package.json", options).unwrap();
        zip.write_all(package_json.as_bytes()).unwrap();

        // Add a dummy extension.js
        zip.start_file("extension/extension.js", options).unwrap();
        zip.write_all(b"// extension code").unwrap();

        zip.finish().unwrap();
    }
    buffer.into_inner()
}

#[test]
fn is_vsix() {
    let vsix = create_vsix(
        r#"{
            "name": "test-extension",
            "publisher": "test-publisher",
            "version": "1.0.0"
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.is_vsix
        }
        "#,
        &vsix
    );
}

#[test]
fn not_vsix() {
    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            not vsix.is_vsix
        }
        "#,
        b"not a vsix file"
    );
}

#[test]
fn basic_fields() {
    let vsix = create_vsix(
        r#"{
            "name": "my-extension",
            "displayName": "My Extension",
            "publisher": "my-publisher",
            "version": "1.2.3",
            "description": "A test extension"
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.name == "my-extension" and
            vsix.display_name == "My Extension" and
            vsix.publisher == "my-publisher" and
            vsix.version == "1.2.3" and
            vsix.id == "my-publisher.my-extension" and
            vsix.description == "A test extension"
        }
        "#,
        &vsix
    );
}

#[test]
fn entry_points() {
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0",
            "main": "./out/extension.js",
            "browser": "./out/browser.js"
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.main == "./out/extension.js" and
            vsix.browser == "./out/browser.js"
        }
        "#,
        &vsix
    );
}

#[test]
fn activation_events() {
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0",
            "activationEvents": ["onCommand:test.run", "*", "onLanguage:rust"]
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.has_activation_event("*") and
            vsix.has_activation_event("onCommand:test.run") and
            not vsix.has_activation_event("nonexistent")
        }
        "#,
        &vsix
    );
}

#[test]
fn activationhash() {
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0",
            "activationEvents": ["onCommand:test.run", "*"]
        }"#,
    );

    // Hash of sorted events with null separators: "*\0onCommand:test.run\0"
    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.activationhash() == "cb9b0f7a2ad019b1701eb4ef983557c0b5b3c05aba9dabedfe16f99df69c9ba8"
        }
        "#,
        &vsix
    );
}

#[test]
fn vscode_version() {
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0",
            "engines": {
                "vscode": "^1.80.0"
            }
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.vscode_version == "^1.80.0"
        }
        "#,
        &vsix
    );
}

#[test]
fn repository_url() {
    // Test repository as object
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0",
            "repository": {
                "type": "git",
                "url": "https://github.com/test/repo"
            }
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.repository == "https://github.com/test/repo"
        }
        "#,
        &vsix
    );

    // Test repository as string
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0",
            "repository": "https://github.com/test/repo2"
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.repository == "https://github.com/test/repo2"
        }
        "#,
        &vsix
    );
}

#[test]
fn categories_and_keywords() {
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0",
            "categories": ["Themes", "Snippets"],
            "keywords": ["rust", "cargo"]
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            for any cat in vsix.categories : (cat == "Themes") and
            for any kw in vsix.keywords : (kw == "rust")
        }
        "#,
        &vsix
    );
}

#[test]
fn files_list() {
    let vsix = create_vsix(
        r#"{
            "name": "test",
            "publisher": "pub",
            "version": "1.0.0"
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            for any f in vsix.files : (f == "extension/package.json") and
            for any f in vsix.files : (f == "extension/extension.js")
        }
        "#,
        &vsix
    );
}

#[test]
fn wildcard_activation_detection() {
    let vsix = create_vsix(
        r#"{
            "name": "suspicious-ext",
            "publisher": "unknown",
            "version": "1.0.0",
            "activationEvents": ["*"]
        }"#,
    );

    rule_true!(
        r#"
        import "vsix"
        rule wildcard_activation {
          condition:
            vsix.is_vsix and
            vsix.has_activation_event("*")
        }
        "#,
        &vsix
    );
}
