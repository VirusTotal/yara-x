import initYaraLs, { runWorkerServer } from "./pkg/yara_x_ls.js";

const READY_MESSAGE_TYPE = "__yara_x_ls_ready__";
const ERROR_MESSAGE_TYPE = "__yara_x_ls_error__";

async function start() {
  try {
    await initYaraLs();
    runWorkerServer();
    postMessage({ type: READY_MESSAGE_TYPE });
  } catch (error) {
    postMessage({
      type: ERROR_MESSAGE_TYPE,
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

void start();
