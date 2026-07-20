import {
  isScanWorkerMessage,
  SCAN_WORKER_MESSAGE_TYPES,
  type ScanWorkerMessage,
} from "./scan-worker.protocol";
import {
  ScanCancelledError,
  type ScanInput,
  type ScanResponse,
  type ScanService,
  type ScanServiceEvents,
} from "./scan-service";

type ActiveRun = {
  runId: number;
  resolve: (response: ScanResponse) => void;
  reject: (error: Error) => void;
};

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export class ScanWorkerClient implements ScanService {
  private worker?: Worker;
  private workerReady?: Promise<void>;
  private resolveWorkerReady?: () => void;
  private rejectWorkerReady?: (error: Error) => void;
  private activeRun?: ActiveRun;
  private nextRunId = 1;
  private readonly events: ScanServiceEvents;

  constructor(events: ScanServiceEvents = {}) {
    this.events = events;
  }

  run(input: ScanInput): Promise<ScanResponse> {
    if (this.activeRun) {
      return Promise.reject(new Error("A scan is already running."));
    }

    const runId = this.nextRunId++;
    this.events.onStage?.("preparing");

    return new Promise((resolve, reject) => {
      this.activeRun = { runId, resolve, reject };

      void this.ensureWorker()
        .then(() => {
          if (this.activeRun?.runId !== runId || !this.worker) {
            return;
          }

          this.worker.postMessage({
            type: SCAN_WORKER_MESSAGE_TYPES.RUN,
            runId,
            input,
          });
        })
        .catch((error: unknown) => {
          this.rejectActiveRun(runId, toError(error));
        });
    });
  }

  cancel(): boolean {
    const activeRun = this.activeRun;

    if (!activeRun) {
      return false;
    }

    this.activeRun = undefined;
    activeRun.reject(new ScanCancelledError());
    this.stopWorker();
    return true;
  }

  dispose() {
    const activeRun = this.activeRun;
    this.activeRun = undefined;
    activeRun?.reject(new ScanCancelledError());
    this.stopWorker();
  }

  private ensureWorker(): Promise<void> {
    if (this.workerReady) {
      return this.workerReady;
    }

    const worker = new Worker(new URL("./scan.worker.ts", import.meta.url), {
      type: "module",
    });

    this.worker = worker;
    this.workerReady = new Promise((resolve, reject) => {
      this.resolveWorkerReady = resolve;
      this.rejectWorkerReady = reject;
    });

    worker.addEventListener("message", (event: MessageEvent<unknown>) => {
      if (this.worker !== worker || !isScanWorkerMessage(event.data)) {
        return;
      }

      this.handleWorkerMessage(event.data);
    });

    worker.addEventListener("error", (event: ErrorEvent) => {
      if (this.worker !== worker) {
        return;
      }

      const error = toError(event.error ?? event.message);
      this.rejectWorkerReady?.(error);
      this.clearWorker();

      if (this.activeRun) {
        this.rejectActiveRun(this.activeRun.runId, error);
      }
    });

    return this.workerReady;
  }

  private handleWorkerMessage(message: ScanWorkerMessage) {
    switch (message.type) {
      case SCAN_WORKER_MESSAGE_TYPES.READY:
        this.resolveWorkerReady?.();
        this.resolveWorkerReady = undefined;
        this.rejectWorkerReady = undefined;
        return;
      case SCAN_WORKER_MESSAGE_TYPES.STATUS:
        if (this.activeRun?.runId === message.runId) {
          this.events.onStage?.(message.stage);
        }
        return;
      case SCAN_WORKER_MESSAGE_TYPES.RESULT:
        if (this.activeRun?.runId === message.runId) {
          const activeRun = this.activeRun;
          this.activeRun = undefined;
          activeRun.resolve(message.response);
        }
        return;
      case SCAN_WORKER_MESSAGE_TYPES.ERROR:
        if (message.runId === null) {
          const error = new Error(message.error);
          this.rejectWorkerReady?.(error);
          this.clearWorker();
          return;
        }

        this.rejectActiveRun(message.runId, new Error(message.error));
    }
  }

  private rejectActiveRun(runId: number, error: Error) {
    if (this.activeRun?.runId !== runId) {
      return;
    }

    const activeRun = this.activeRun;
    this.activeRun = undefined;
    activeRun.reject(error);
  }

  private stopWorker() {
    this.rejectWorkerReady?.(new ScanCancelledError());
    this.clearWorker();
  }

  private clearWorker() {
    this.worker?.terminate();
    this.worker = undefined;
    this.workerReady = undefined;
    this.resolveWorkerReady = undefined;
    this.rejectWorkerReady = undefined;
  }
}

export function createScanWorkerClient(
  events?: ScanServiceEvents,
): ScanService {
  return new ScanWorkerClient(events);
}
