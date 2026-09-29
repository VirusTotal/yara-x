import {
  isLanguageServerWorkerBootstrapMessage,
  LANGUAGE_SERVER_WORKER_MESSAGE_TYPES,
} from "./language-server-worker.protocol";

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

export function createLanguageServerWorker(): Promise<Worker> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      new URL("./language-server.worker.ts", import.meta.url),
      {
        type: "module",
      },
    );

    const cleanup = () => {
      worker.removeEventListener("message", onMessage);
      worker.removeEventListener("error", onError);
    };

    const onMessage = (event: MessageEvent<unknown>) => {
      if (!isLanguageServerWorkerBootstrapMessage(event.data)) {
        return;
      }

      if (event.data.type === LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.READY) {
        cleanup();
        resolve(worker);
        return;
      }

      if (event.data.type === LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.ERROR) {
        cleanup();
        worker.terminate();
        reject(formatWorkerError(event.data.error));
      }
    };

    const onError = (event: ErrorEvent) => {
      cleanup();
      worker.terminate();
      reject(
        formatWorkerError(
          event.error ?? event.message ?? "Worker bootstrap failled.",
        ),
      );
    };

    worker.addEventListener("message", onMessage);
    worker.addEventListener("error", onError);
  });
}
