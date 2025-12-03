use std::path::PathBuf;

use crate::tests::{start_server, DeserializableTestDefinition};
use async_lsp::lsp_types::request::SelectionRangeRequest;
use async_lsp::lsp_types::{SelectionRange, SelectionRangeParams};
use async_lsp::LanguageServer;
use serde::Deserialize;

#[derive(Deserialize)]
struct SelectionRangeTestDefinition {
    params: SelectionRangeParams,
    expected: Option<Vec<SelectionRange>>,
}

impl DeserializableTestDefinition for SelectionRangeTestDefinition {}

macro_rules! selection_range_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data = SelectionRangeTestDefinition::from_file(
                &testpath.with_extension("json"),
            )
            .unwrap();

            let result = server_socket
                .request::<SelectionRangeRequest>(test_data.params)
                .await;
            let selection_range_response_option =
                result.expect("Failed: Server responded with error");

            assert!(
                selection_range_response_option.is_some()
                    == test_data.expected.is_some(),
                "Failed: unexpected presence of selection range response"
            );

            if let Some(expected_response) = test_data.expected {
                let result_response = selection_range_response_option
                    .expect("Failed: no selection range found");

                assert!(
                    expected_response == result_response,
                    "Failed: selection range does not match expected value"
                )
            }

            server_socket
                .shutdown(())
                .await
                .expect("Failed to shutdown server");
            server_socket.exit(()).expect("Failed to exit server");

            server_thread.await.expect("Server thread panicked");
            client_thread.await.expect("Client thread panicked");
        }
    };
}

selection_range_test!(
    "src/tests/testdata/selectionrange/selectionrange1.yar",
    selection_range_simple
);

selection_range_test!(
    "src/tests/testdata/selectionrange/selectionrange2.yar",
    selection_range_from_pattern
);

selection_range_test!(
    "src/tests/testdata/selectionrange/selectionrange3.yar",
    selection_range_from_meta
);

selection_range_test!(
    "src/tests/testdata/selectionrange/selectionrange4.yar",
    selection_range_within_expression
);

selection_range_test!(
    "src/tests/testdata/selectionrange/selectionrange5.yar",
    selection_range_comment
);

selection_range_test!(
    "src/tests/testdata/selectionrange/selectionrange6.yar",
    selection_rule_tags
);

selection_range_test!(
    "src/tests/testdata/selectionrange/selectionrange7.yar",
    selection_pattern_modifiers
);
