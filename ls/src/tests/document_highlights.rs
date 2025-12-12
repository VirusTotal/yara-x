use std::path::PathBuf;

use crate::tests::{start_server, DeserializableTestDefinition};
use async_lsp::lsp_types::request::DocumentHighlightRequest;
use async_lsp::lsp_types::{DocumentHighlight, DocumentHighlightParams};
use async_lsp::LanguageServer;
use serde::Deserialize;

#[derive(Deserialize)]
struct DocumentHighlightsTestDefinition {
    params: DocumentHighlightParams,
    expected: Option<Vec<DocumentHighlight>>,
}

impl DeserializableTestDefinition for DocumentHighlightsTestDefinition {}

macro_rules! document_highlights_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data = DocumentHighlightsTestDefinition::from_file(
                &testpath.with_extension("json"),
            )
            .unwrap();

            let result = server_socket
                .request::<DocumentHighlightRequest>(test_data.params)
                .await;
            let document_highlights_response_option =
                result.expect("Failed: Server responded with error");

            assert!(
                document_highlights_response_option.is_some()
                    == test_data.expected.is_some(),
                "Failed: unexpected presence of document highlights response"
            );

            if let Some(expected_response) = test_data.expected {
                let result_response = document_highlights_response_option
                    .expect("Failed: no document highlights found");

                expected_response.iter().for_each(|document_highlight| {
                    assert!(
                        result_response.contains(document_highlight),
                        "Failed: missing expected document highlight: {document_highlight:?}",
                    );
                });
            }

            server_socket.shutdown(()).await.expect("Failed to shutdown server");
            server_socket.exit(()).expect("Failed to exit server");

            server_thread.await.expect("Server thread panicked");
            client_thread.await.expect("Client thread panicked");
        }
    };
}

document_highlights_test!(
    "src/tests/testdata/documenthighlights/documenthighlights1.yar",
    document_highlights_rule_identifier
);

document_highlights_test!(
    "src/tests/testdata/documenthighlights/documenthighlights2.yar",
    document_highlights_rule_identifier_multiple_occurrences
);

document_highlights_test!(
    "src/tests/testdata/documenthighlights/documenthighlights3.yar",
    document_highlights_pattern_identifier
);

document_highlights_test!(
    "src/tests/testdata/documenthighlights/documenthighlights4.yar",
    document_highlights_pattern_identifier_multiple_occurrences
);

document_highlights_test!(
    "src/tests/testdata/documenthighlights/documenthighlights5.yar",
    document_highlights_similar_pattern_identifiers
);
