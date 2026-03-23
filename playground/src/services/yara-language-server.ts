/**
 * Playground-facing contract for the browser language server integration.
 *
 * TODO(@kevinmuoz): Confirm with Victor whether the browser language server
 * should be published as a separate npm package or bundled only as part of the
 * official playground. Keep this interface Monaco-agnostic either way.
 *
 * Possible future config:
 *
 * const languageServer = getYaraLanguageServer();
 * const worker = await languageServer.createWorker();
 *
 */
export interface YaraLanguageServer {
  /**
   * Returns a ready-to-use worker that can be connected directly to an LSP
   * client. Any package-specific bootstrap or readiness handshake should stay
   * hidden behind this contract.
   */
  createWorker(): Promise<Worker>;
}
