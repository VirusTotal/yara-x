import { isRecord } from "../validation/guards";
import type {
  ScanInput,
  ScanProgressStage,
  ScanResponse,
} from "./scan-service";

export const SCAN_WORKER_MESSAGE_TYPES = {
  READY: "yara-x/scan/ready",
  STATUS: "yara-x/scan/status",
  RESULT: "yara-x/scan/result",
  ERROR: "yara-x/scan/error",
  RUN: "yara-x/scan/run",
} as const;

export type ScanWorkerRequest = {
  type: typeof SCAN_WORKER_MESSAGE_TYPES.RUN;
  runId: number;
  input: ScanInput;
};

export type ScanWorkerMessage =
  | {
      type: typeof SCAN_WORKER_MESSAGE_TYPES.READY;
    }
  | {
      type: typeof SCAN_WORKER_MESSAGE_TYPES.STATUS;
      runId: number;
      stage: Exclude<ScanProgressStage, "idle">;
    }
  | {
      type: typeof SCAN_WORKER_MESSAGE_TYPES.RESULT;
      runId: number;
      response: ScanResponse;
    }
  | {
      type: typeof SCAN_WORKER_MESSAGE_TYPES.ERROR;
      runId: number | null;
      error: string;
    };

export function isScanWorkerMessage(
  value: unknown,
): value is ScanWorkerMessage {
  if (!isRecord(value)) {
    return false;
  }

  return (
    value.type === SCAN_WORKER_MESSAGE_TYPES.READY ||
    value.type === SCAN_WORKER_MESSAGE_TYPES.STATUS ||
    value.type === SCAN_WORKER_MESSAGE_TYPES.RESULT ||
    value.type === SCAN_WORKER_MESSAGE_TYPES.ERROR
  );
}

export function isScanWorkerRequest(
  value: unknown,
): value is ScanWorkerRequest {
  return (
    isRecord(value) &&
    value.type === SCAN_WORKER_MESSAGE_TYPES.RUN &&
    typeof value.runId === "number" &&
    "input" in value
  );
}
