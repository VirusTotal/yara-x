/**
 * Playground-facing contract for the browser language server integration.
 */
export interface YaraLanguageServer {
  /**
   * Returns a ready-to-use worker that can be connected directly to an LSP
   * client. Any browser-specific bootstrap or readiness handshake stays hidden
   * behind this contract so the editor integration remains transport-agnostic.
   */
  createWorker(): Promise<Worker>;
}
