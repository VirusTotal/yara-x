import initYara, {
  Compiler as WasmCompiler,
  Rules as WasmRules,
  Scanner as WasmScanner,
} from "@virustotal/yara-x";
import {
  isScanWorkerRequest,
  SCAN_WORKER_MESSAGE_TYPES,
  type ScanWorkerRequest,
} from "./scan-worker.protocol";
import type { ScanInput, ScanResponse } from "./scan-service";
import { decodeSampleInput } from "../sample/decode-sample";

let activeRunId: number | undefined;

const initPromise = initYara();

function formatConsoleValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (value instanceof Error) return value.stack ?? value.message;

  if (typeof value === "object" && value !== null) {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  return String(value);
}

function formatConsoleEntry(args: unknown[]): string {
  return args.map(formatConsoleValue).join(" ");
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function postStatus(
  runId: number,
  stage: "reading" | "compiling" | "scanning",
) {
  postMessage({
    type: SCAN_WORKER_MESSAGE_TYPES.STATUS,
    runId,
    stage,
  });
}

async function readSample(input: ScanInput): Promise<Uint8Array> {
  if (input.sample.mode === "file") {
    return new Uint8Array(await input.sample.file.arrayBuffer());
  }

  return decodeSampleInput(input.sample.mode, input.sample.source);
}

function scan(input: ScanInput, payload: Uint8Array): ScanResponse {
  let compiler: WasmCompiler | undefined;
  let rules: WasmRules | undefined;
  let scanner: WasmScanner | undefined;
  const consoleOutput: string[] = [];

  try {
    compiler = new WasmCompiler();
    compiler.addSource(input.ruleSource);
    rules = compiler.build();
    scanner = rules.scanner();

    if (input.maxMatchesPerPattern != null) {
      scanner.setMaxMatchesPerPattern(input.maxMatchesPerPattern);
    }

    const originalConsoleLog = console.log;

    try {
      // This global interception is not ideal, but it is scoped to this worker.
      // YARA-X logs synchronously during the scan, so restore it before another
      // worker message is handled. App and Monaco logs use other contexts.
      console.log = (...args: Parameters<typeof console.log>) => {
        consoleOutput.push(formatConsoleEntry(args));
        originalConsoleLog.apply(console, args);
      };

      return {
        raw: scanner.scan(payload),
        consoleOutput,
      };
    } finally {
      console.log = originalConsoleLog;
    }
  } finally {
    scanner?.free();
    rules?.free();
    compiler?.free();
  }
}

async function runScan(request: ScanWorkerRequest) {
  try {
    await initPromise;
    postStatus(request.runId, "reading");
    const payload = await readSample(request.input);
    postStatus(request.runId, "compiling");

    postStatus(request.runId, "scanning");
    const response = scan(request.input, payload);

    postMessage({
      type: SCAN_WORKER_MESSAGE_TYPES.RESULT,
      runId: request.runId,
      response,
    });
  } catch (error) {
    postMessage({
      type: SCAN_WORKER_MESSAGE_TYPES.ERROR,
      runId: request.runId,
      error: formatError(error),
    });
  } finally {
    activeRunId = undefined;
  }
}

void initPromise.then(
  () => {
    postMessage({ type: SCAN_WORKER_MESSAGE_TYPES.READY });
  },
  (error: unknown) => {
    postMessage({
      type: SCAN_WORKER_MESSAGE_TYPES.ERROR,
      runId: null,
      error: formatError(error),
    });
  },
);

self.addEventListener("message", (event: MessageEvent<unknown>) => {
  if (!isScanWorkerRequest(event.data)) {
    return;
  }

  if (activeRunId != null) {
    postMessage({
      type: SCAN_WORKER_MESSAGE_TYPES.ERROR,
      runId: event.data.runId,
      error: "A scan is already running.",
    });
    return;
  }

  activeRunId = event.data.runId;
  void runScan(event.data);
});
