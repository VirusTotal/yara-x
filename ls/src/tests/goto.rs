use std::path::PathBuf;

use crate::tests::{start_server, DeserializableTestDefinition};
use async_lsp::lsp_types::{
    request::GotoDefinition, GotoDefinitionParams, GotoDefinitionResponse,
};
use async_lsp::LanguageServer;
use serde::Deserialize;

#[derive(Deserialize)]
struct GotoTestDefinition {
    params: GotoDefinitionParams,
    expected: Option<GotoDefinitionResponse>,
}

impl DeserializableTestDefinition for GotoTestDefinition {}

macro_rules! goto_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data = GotoTestDefinition::from_file(
                &testpath.with_extension("json"),
            )
            .unwrap();

            let result = server_socket
                .request::<GotoDefinition>(test_data.params)
                .await;
            let goto_response_option =
                result.expect("Failed: Server responded with error");

            assert!(
                goto_response_option.is_some() == test_data.expected.is_some(),
                "Failed: unexpected presence of go to definition response"
            );

            if let Some(expected_response) = test_data.expected {
                let result_response =
                    goto_response_option.expect("Failed: no definition found");

                assert!(
                    expected_response == result_response,
                    "Failed: go to definition does not match expected value"
                );
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

goto_test!("src/tests/testdata/goto/goto1.yar", goto_pattern_identifier);

goto_test!("src/tests/testdata/goto/goto2.yar", goto_rule_identifier);

goto_test!(
    "src/tests/testdata/goto/goto3.yar",
    goto_similar_pattern_identifiers
);

goto_test!(
    "src/tests/testdata/goto/goto4.yar",
    goto_multiple_identifier_usages
);

goto_test!("src/tests/testdata/goto/goto5.yar", goto_no_location_found);
