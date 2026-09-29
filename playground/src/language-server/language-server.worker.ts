import initYaraLs, {
  runWorkerServer,
} from "../wasm/yara-x-ls/pkg/yara_x_ls.js";
import { LANGUAGE_SERVER_WORKER_MESSAGE_TYPES } from "./language-server-worker.protocol";

async function main() {
  await initYaraLs();
  runWorkerServer();
  postMessage({ type: LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.READY });
}

void main().catch((error) => {
  postMessage({
    type: LANGUAGE_SERVER_WORKER_MESSAGE_TYPES.ERROR,
    error: error instanceof Error ? error.message : String(error),
  });
  console.error("failed to start yara-x-ls worker", error);
});
