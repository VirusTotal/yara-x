use std::path::PathBuf;

use async_lsp::lsp_types::{request::Rename, RenameParams, WorkspaceEdit};
use async_lsp::LanguageServer;
use serde::Deserialize;

use crate::tests::start_server;
use crate::tests::DeserializableTestDefinition;

#[derive(Deserialize)]
struct RenameTestDefinition {
    params: RenameParams,
    expected: Option<WorkspaceEdit>,
}

impl DeserializableTestDefinition for RenameTestDefinition {}

macro_rules! rename_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data = RenameTestDefinition::from_file(
                &testpath.with_extension("json"),
            )
            .unwrap();

            let result =
                server_socket.request::<Rename>(test_data.params).await;

            let workspace_edit_option =
                result.expect("Failed: Server responded with error");

            assert!(
                workspace_edit_option.is_some()
                    == test_data.expected.is_some(),
                "Failed: unexpected presence of workspace edit"
            );
            if test_data.expected.is_none() {
                return;
            }

            let result_workspace_edit =
                workspace_edit_option.expect("Failed: workspace edit is none");

            let expected_workspace_edit = test_data.expected.unwrap();

            assert!(
                expected_workspace_edit.changes.is_some()
                    == result_workspace_edit.changes.is_some(),
                "Failed: changes is different than expected"
            );

            if let Some(expected_changes) = expected_workspace_edit.changes {
                let result_changes = result_workspace_edit
                    .changes
                    .expect("Failed: no changes in the result workspace edit");

                assert!(
                    expected_changes.len() == result_changes.len(),
                    "Failed: unexpected number of changed files"
                );

                for (url, expected_text_edits) in expected_changes {
                    let result_text_edits = result_changes.get(&url).expect(
                        "Failed: changed file url not found in result",
                    );

                    assert!(
                        expected_text_edits.len() == result_text_edits.len(),
                        "Failed: unexpected number of changes in the {}",
                        url.as_str()
                    );

                    expected_text_edits.iter().for_each(|expected_edit| {
                        assert!(
                            result_text_edits.contains(expected_edit),
                            "Failed: expected text edit not found in the result"
                        );
                    });
                }
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

rename_test!(
    "src/tests/testdata/rename/rename1.yar",
    rename_pattern_identifier
);

rename_test!(
    "src/tests/testdata/rename/rename2.yar",
    rename_pattern_identifier_multiple_occurrences
);

rename_test!("src/tests/testdata/rename/rename3.yar", rename_rule_identifier);

rename_test!(
    "src/tests/testdata/rename/rename4.yar",
    rename_rule_identifier_multiple_occurrences
);

rename_test!(
    "src/tests/testdata/rename/rename4.yar",
    rename_no_identifier_found
);
