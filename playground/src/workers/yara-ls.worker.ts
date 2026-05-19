import initYaraLs, {
  runWorkerServer,
} from "../wasm/yara-x-ls/pkg/yara_x_ls.js";
import { ERROR_MESSAGE_TYPE, READY_MESSAGE_TYPE } from "./yara-ls.messages";

async function main() {
  await initYaraLs();
  runWorkerServer();
  postMessage({ type: READY_MESSAGE_TYPE });
}

void main().catch((error) => {
  postMessage({
    type: ERROR_MESSAGE_TYPE,
    error: error instanceof Error ? error.message : String(error),
  });
  console.error("failed to start yara-x-ls worker", error);
});
