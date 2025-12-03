use std::path::PathBuf;

use async_lsp::lsp_types::request::Completion;
use async_lsp::lsp_types::{
    CompletionList, CompletionParams, CompletionResponse,
};
use async_lsp::LanguageServer;
use serde::Deserialize;

use crate::tests::start_server;
use crate::tests::DeserializableTestDefinition;

#[derive(Deserialize)]
struct CompletionTestDefinition {
    params: CompletionParams,
    expected: Option<CompletionResponse>,
}

impl DeserializableTestDefinition for CompletionTestDefinition {}

macro_rules! completion_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data =
                CompletionTestDefinition::from_file(&testpath.with_extension("json"))
                    .unwrap();

            let result = server_socket.request::<Completion>(test_data.params).await;

            let completion_edit_option =
                result.expect("Failed: Server responded with error");

            assert!(
                completion_edit_option.is_some() == test_data.expected.is_some(),
                "Failed: unexpected presence of completion response"
            );

            match test_data.expected {
                Some(CompletionResponse::Array(items))
                | Some(CompletionResponse::List(CompletionList { items, .. })) => {
                    let result_reponse = match completion_edit_option {
                        Some(CompletionResponse::Array(res_items))
                        | Some(CompletionResponse::List(CompletionList {
                            items: res_items,
                            ..
                        })) => res_items,
                        None => panic!("Failed: expected completion response"),
                    };

                    items.iter().for_each(|expected_item| {
                        assert!(
                            result_reponse.contains(expected_item),
                            "Failed: completion item {expected_item:?} not found in result",
                        );
                    });
                }
                None => {}
            }

            server_socket.shutdown(()).await.expect("Failed to shutdown server");
            server_socket.exit(()).expect("Failed to exit server");

            server_thread.await.expect("Server thread panicked");
            client_thread.await.expect("Client thread panicked");
        }
    };
}

completion_test!(
    "src/tests/testdata/completion/completion1.yar",
    completion_top_level_keywords
);

completion_test!(
    "src/tests/testdata/completion/completion2.yar",
    completion_condition_rule_and_keywords
);

completion_test!(
    "src/tests/testdata/completion/completion3.yar",
    completion_pattern_identifier
);

completion_test!(
    "src/tests/testdata/completion/completion4.yar",
    completion_pattern_modifiers
);

completion_test!(
    "src/tests/testdata/completion/completion5.yar",
    completion_rule_block_keywords
);
