use std::path::PathBuf;

use crate::tests::{start_server, DeserializableTestDefinition};
use async_lsp::lsp_types::request::References;
use async_lsp::lsp_types::{Location, ReferenceParams};
use async_lsp::LanguageServer;
use serde::Deserialize;

#[derive(Deserialize)]
struct ReferencesTestDefinition {
    params: ReferenceParams,
    expected: Option<Vec<Location>>,
}

impl DeserializableTestDefinition for ReferencesTestDefinition {}

macro_rules! references_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data =
                ReferencesTestDefinition::from_file(&testpath.with_extension("json"))
                    .unwrap();

            let result = server_socket.request::<References>(test_data.params).await;
            let references_response_option =
                result.expect("Failed: Server responded with error");

            assert!(
                references_response_option.is_some() == test_data.expected.is_some(),
                "Failed: unexpected presence of reference response"
            );
            if test_data.expected.is_none() {
                return;
            }

            if let Some(expected_response) = test_data.expected {
                let result_response =
                    references_response_option.expect("Failed: no references found");

                assert!(
                    result_response.len() == expected_response.len(),
                    "Failed: number of references does not match expected value"
                );

                expected_response.iter().for_each(|location| {
                    assert!(
                        result_response.contains(location),
                        "Failed: reference {location:?} not found in result",
                    )
                });
            }

            server_socket.shutdown(()).await.expect("Failed to shutdown server");
            server_socket.exit(()).expect("Failed to exit server");

            server_thread.await.expect("Server thread panicked");
            client_thread.await.expect("Client thread panicked");
        }
    };
}

references_test!(
    "src/tests/testdata/references/references1.yar",
    references_pattern_identifier
);

references_test!(
    "src/tests/testdata/references/references2.yar",
    references_pattern_identifier_multiple_usages
);

references_test!(
    "src/tests/testdata/references/references3.yar",
    references_rule_identifier
);

references_test!(
    "src/tests/testdata/references/references4.yar",
    references_rule_identifier_multiple_usages
);

references_test!(
    "src/tests/testdata/references/references5.yar",
    references_similar_pattern_identifiers
);
