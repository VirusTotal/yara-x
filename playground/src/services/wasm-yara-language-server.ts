import type { YaraLanguageServer } from "./yara-language-server";

export function getWasmYaraLanguageServer(): YaraLanguageServer {
  return {
    async createWorker() {
      /**
       * TODO(@kevinmuoz): I'll Replace this placeholder once the browser
       * worker entrypoint for "yara-x-ls" is upstream and we agree on how it
       * should be distributed to web consumers. "createWorker()"" must keep
       * resolving only once the worker is ready to accept LSP traffic
       *
       * Possible future config:
       *
       * import { createWorker } from "@virustotal/yara-x-ls-web";
       *
       * const worker = await createWorker();
       */
      throw new Error(
        "TODO(@kevinmuoz): wire the browser language-server package once the upstream worker entrypoint is published.",
      );
    },
  };
}
