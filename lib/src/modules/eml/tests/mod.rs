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
fn encoded_words() {
    let eml = b"From: =?UTF-8?B?SsO8cmdlbg==?= <j@example.com>\r\n\
                Subject: =?ISO-8859-1?Q?Caf=E9_menu?=\r\n\
                \r\n\
                body";

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.from[0].name == "Jürgen" and
            eml.from[0].address == "j@example.com" and
            eml.subject == "Café menu" and
            eml.headers[1].value == "=?ISO-8859-1?Q?Caf=E9_menu?="
        }
        "#,
        eml.as_slice()
    );
}

#[test]
fn part_fields() {
    let eml = create_binary_from_zipped_ihex(
        "src/modules/eml/tests/testdata/1bd008595eefab8ab0653ccaeac7857989178d75f842f8b147b6cc7e1701aca5.in.zip",
    );

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.parts[0].content_type == "text/plain" and
            eml.parts[0].charset == "UTF-8" and
            eml.parts[0].size == 143 and
            not defined eml.parts[0].content_id and
            eml.parts[2].content_type == "text/html" and
            eml.parts[2].disposition == "attachment" and
            eml.parts[2].size == 172
        }
        "#,
        &eml
    );
}

#[test]
fn part_content_id_and_decoded_size() {
    let eml = b"Content-Type: multipart/related; boundary=\"b\"\r\n\
                \r\n\
                --b\r\n\
                Content-Type: IMAGE/PNG\r\n\
                Content-ID: <logo@example.com>\r\n\
                Content-Transfer-Encoding: base64\r\n\
                \r\n\
                aGVsbG8=\r\n\
                --b--\r\n";

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.parts[0].content_type == "image/png" and
            eml.parts[0].content_id == "logo@example.com" and
            eml.parts[0].size == 5
        }
        "#,
        eml.as_slice()
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
