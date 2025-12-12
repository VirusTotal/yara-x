use std::path::PathBuf;

use crate::tests::{start_server, DeserializableTestDefinition};
use async_lsp::lsp_types::request::DocumentSymbolRequest;
use async_lsp::lsp_types::{DocumentSymbolParams, DocumentSymbolResponse};
use async_lsp::LanguageServer;
use serde::Deserialize;

#[derive(Deserialize)]
struct DocumentSymbolTestDefinition {
    params: DocumentSymbolParams,
    expected: Option<DocumentSymbolResponse>,
}

impl DeserializableTestDefinition for DocumentSymbolTestDefinition {}

macro_rules! document_symbols_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data = DocumentSymbolTestDefinition::from_file(
                &testpath.with_extension("json"),
            )
            .unwrap();

            let result = server_socket
                .request::<DocumentSymbolRequest>(test_data.params)
                .await;
            let document_symbol_response_option =
                result.expect("Failed: Server responded with error");

            assert!(
                document_symbol_response_option.is_some()
                    == test_data.expected.is_some(),
                "Failed: unexpected presence of document symbol response"
            );

            if let Some(expected_response) = test_data.expected {
                let result_response = document_symbol_response_option
                    .expect("Failed: no document symbols found");

                assert!(
                    expected_response == result_response,
                    "Failed: unexpected document symbols response"
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

document_symbols_test!(
    "src/tests/testdata/documentsymbols/documentsymbols1.yar",
    document_symbols_import
);

document_symbols_test!(
    "src/tests/testdata/documentsymbols/documentsymbols2.yar",
    document_symbols_include
);

document_symbols_test!(
    "src/tests/testdata/documentsymbols/documentsymbols3.yar",
    document_symbols_rule_definition
);

document_symbols_test!(
    "src/tests/testdata/documentsymbols/documentsymbols4.yar",
    document_symbols_import_include_rule
);

document_symbols_test!(
    "src/tests/testdata/documentsymbols/documentsymbols5.yar",
    document_symbols_rule_with_pattern
);

document_symbols_test!(
    "src/tests/testdata/documentsymbols/documentsymbols6.yar",
    document_symbols_rule_with_multiple_patterns
);

document_symbols_test!(
    "src/tests/testdata/documentsymbols/documentsymbols7.yar",
    document_symbols_complex
);
