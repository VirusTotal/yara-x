use std::path::PathBuf;

use crate::tests::{start_server, DeserializableTestDefinition};
use async_lsp::lsp_types::{request::HoverRequest, Hover, HoverParams};
use async_lsp::LanguageServer;
use serde::Deserialize;

#[derive(Deserialize)]
struct HoverTestDefinition {
    params: HoverParams,
    expected: Option<Hover>,
}

impl DeserializableTestDefinition for HoverTestDefinition {}

macro_rules! hover_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data = HoverTestDefinition::from_file(
                &testpath.with_extension("json"),
            )
            .unwrap();

            let result =
                server_socket.request::<HoverRequest>(test_data.params).await;
            let hover_response_option =
                result.expect("Failed: Server responded with error");

            assert!(
                hover_response_option.is_some()
                    == test_data.expected.is_some(),
                "Failed: unexpected presence of hover response"
            );
            if test_data.expected.is_none() {
                return;
            }

            if let Some(expected_response) = test_data.expected {
                let result_response = hover_response_option
                    .expect("Failed: no definition found");

                assert!(
                    expected_response == result_response,
                    "Failed: hover does not match expected value",
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

hover_test!("src/tests/testdata/hover/hover1.yar", hover_pattern_identifier);

hover_test!("src/tests/testdata/hover/hover2.yar", hover_rule_one_line);

hover_test!(
    "src/tests/testdata/hover/hover3.yar",
    hover_multiline_pattern_definition
);

hover_test!("src/tests/testdata/hover/hover4.yar", hover_multiline_condition);

hover_test!("src/tests/testdata/hover/hover5.yar", hover_pattern_modifiers);

hover_test!("src/tests/testdata/hover/hover6.yar", hover_complex_rule);
