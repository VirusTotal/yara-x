use crate::tests;
use tests::*;

#[test]
#[cfg(feature = "hash-module")]
fn test_hash_module() {
    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.md5(0, filesize) == "6df23dc03f9b54cc38a0fc1483df6e21" and
            hash.md5(3, 3) == "37b51d194a7513e45b56f6524f2d51f2" and
            hash.md5(0, filesize) == hash.md5("foobarbaz") and
            hash.md5(3, 3) == hash.md5("bar")
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.sha1(0, filesize) == "5f5513f8822fdbe5145af33b64d8d970dcf95c6e" and
            hash.sha1(3, 3) == "62cdb7020ff920e5aa642c3d4066950dd1f01f4d" and
            hash.sha1(0, filesize) == hash.sha1("foobarbaz") and
            hash.sha1(3, 3) == hash.sha1("bar")
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.sha256(0, filesize) == "97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d" and
            hash.sha256(3, 3) == "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9" and
            hash.sha256(0, filesize) == hash.sha256("foobarbaz") and
            hash.sha256(3, 3) == hash.sha256("bar")
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.crc32(0, filesize) == 0x1a7827aa and
            hash.crc32(3, 3) == 0x76ff8caa and
            hash.crc32(0, filesize) == hash.crc32("foobarbaz") and
            hash.crc32(3, 3) ==  hash.crc32("bar")
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.checksum32("TEST STRING") == 0x337
        }
        "#,
        b"foobarbaz"
    );

    rule_true!(
        r#"
        import "hash"
        rule test {
          condition:
            hash.checksum32(0, filesize) == 0x337
        }
        "#,
        b"TEST STRING"
    );
}
