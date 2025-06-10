import "test_proto2"import "test_proto3"rule t {condition: with foo = test_proto2.uppercase("foo"): (foo == "FOO" ) }
