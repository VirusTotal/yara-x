use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn has_header() {
    let eml = create_binary_from_zipped_ihex(
        "src/modules/eml/tests/testdata/1bd008595eefab8ab0653ccaeac7857989178d75f842f8b147b6cc7e1701aca5.in.zip",
    );

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.has_header("date")
        }
        "#,
        &eml
    );
}

#[test]
fn convenience_fields() {
    let eml = create_binary_from_zipped_ihex(
        "src/modules/eml/tests/testdata/1bd008595eefab8ab0653ccaeac7857989178d75f842f8b147b6cc7e1701aca5.in.zip",
    );

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.from[0].name == "Jane Doe" and
            eml.from[0].address == "sender@example.com" and
            eml.to[0].name == "John Smith" and
            eml.to[0].address == "recipient@example.com" and
            eml.return_path.address == "sender@example.com" and
            not defined eml.return_path.name and
            eml.subject == "Meeting Agenda & Attached Report" and
            eml.date == "Sat, 25 Jul 2026 10:15:00 -0400" and
            not defined eml.message_id and
            not defined eml.cc[0].address
        }
        "#,
        &eml
    );
}
