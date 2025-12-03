use std::path::PathBuf;

use crate::tests::{start_server, DeserializableTestDefinition};
use async_lsp::lsp_types::request::DocumentDiagnosticRequest;
use async_lsp::lsp_types::{
    DocumentDiagnosticParams, DocumentDiagnosticReportResult,
};
use async_lsp::LanguageServer;
use serde::Deserialize;

#[derive(Deserialize)]
struct DiagnosticsTestDefinition {
    params: DocumentDiagnosticParams,
    expected: DocumentDiagnosticReportResult,
}

impl DeserializableTestDefinition for DiagnosticsTestDefinition {}

macro_rules! diagnostics_test {
    ($file: literal, $name: ident) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let testpath = PathBuf::from($file);
            let (mut server_socket, client_thread, server_thread) =
                start_server(&testpath).await;

            let test_data = DiagnosticsTestDefinition::from_file(
                &testpath.with_extension("json"),
            )
            .unwrap();

            let result = server_socket
                .request::<DocumentDiagnosticRequest>(test_data.params)
                .await;
            let diagnostics_response_option =
                result.expect("Failed: Server responded with error");

            assert!(
                test_data.expected == diagnostics_response_option,
                "Failed: unexpected diagnostics response",
            );

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

diagnostics_test!(
    "src/tests/testdata/diagnostics/diagnostics1.yar",
    diagnostics_no_error
);

diagnostics_test!(
    "src/tests/testdata/diagnostics/diagnostics2.yar",
    diagnostics_syntax
);

diagnostics_test!(
    "src/tests/testdata/diagnostics/diagnostics3.yar",
    diagnostics_undefined_pattern
);

diagnostics_test!(
    "src/tests/testdata/diagnostics/diagnostics4.yar",
    diagnostics_unused_pattern
);

diagnostics_test!(
    "src/tests/testdata/diagnostics/diagnostics5.yar",
    diagnostics_duplicate_pattern_definition
);
