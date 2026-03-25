const READY_MESSAGE_TYPE = "__yara_x_ls_ready__";
const ERROR_MESSAGE_TYPE = "__yara_x_ls_error__";

function formatWorkerError(error) {
  if (error instanceof Error) {
    return error;
  }

  return new Error(
    typeof error === "string"
      ? error
      : "Failed to start the YARA-X language server worker.",
  );
}

export function createWorker() {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./worker.js", import.meta.url), {
      type: "module",
    });

    const cleanup = () => {
      worker.removeEventListener("message", onMessage);
      worker.removeEventListener("error", onError);
    };

    const onMessage = (event) => {
      const data = event.data;

      if (!data || typeof data !== "object") {
        return;
      }

      if (data.type === READY_MESSAGE_TYPE) {
        cleanup();
        resolve(worker);
        return;
      }

      if (data.type === ERROR_MESSAGE_TYPE) {
        cleanup();
        worker.terminate();
        reject(formatWorkerError(data.error));
      }
    };

    const onError = (event) => {
      cleanup();
      worker.terminate();
      reject(
        formatWorkerError(event.error ?? event.message ?? "Worker bootstrap failed."),
      );
    };

    worker.addEventListener("message", onMessage);
    worker.addEventListener("error", onError);
  });
}
