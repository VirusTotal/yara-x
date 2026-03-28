import {
  ERROR_MESSAGE_TYPE,
  READY_MESSAGE_TYPE,
} from "../workers/yara-ls.messages";

import type { YaraLanguageServer } from "./yara-language-server";

function formatWorkerError(error: unknown) {
  if (error instanceof Error) {
    return error;
  }

  return new Error(
    typeof error === "string"
      ? error
      : "Failed to start the YARA-X language server worker.",
  );
}

export function getWasmYaraLanguageServer(): YaraLanguageServer {
  return {
    async createWorker() {
      return new Promise((resolve, reject) => {
        const worker = new Worker(
          new URL("../workers/yara-ls.worker.ts", import.meta.url),
          {
            type: "module",
          },
        );

        const cleanup = () => {
          worker.removeEventListener("message", onMessage);
          worker.removeEventListener("error", onError);
        };

        const onMessage = (event: MessageEvent<unknown>) => {
          const data = event.data;

          if (!data || typeof data !== "object") {
            return;
          }

          if ("type" in data && data.type === READY_MESSAGE_TYPE) {
            cleanup();
            resolve(worker);
            return;
          }

          if ("type" in data && data.type === ERROR_MESSAGE_TYPE) {
            cleanup();
            worker.terminate();
            reject(
              formatWorkerError(
                "error" in data ? data.error : "Worker bootstrap failed.",
              ),
            );
          }
        };

        const onError = (event: ErrorEvent) => {
          cleanup();
          worker.terminate();
          reject(
            formatWorkerError(
              event.error ?? event.message ?? "Worker bootstrap failed.",
            ),
          );
        };

        worker.addEventListener("message", onMessage);
        worker.addEventListener("error", onError);
      });
    },
  };
}
