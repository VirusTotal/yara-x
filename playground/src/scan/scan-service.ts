import type { InlineSampleMode } from "../sample/sample-modes";

export type ScanProgressStage =
  | "idle"
  | "preparing"
  | "reading"
  | "compiling"
  | "scanning";

export type ScanSample =
  | {
      mode: InlineSampleMode;
      source: string;
    }
  | {
      mode: "file";
      file: File;
    };

export type ScanInput = {
  ruleSource: string;
  sample: ScanSample;
  maxMatchesPerPattern: number | null;
};

export type ScanResponse = {
  raw: unknown;
  consoleOutput: string[];
};

export type ScanServiceEvents = {
  onStage?: (stage: ScanProgressStage) => void;
};

export interface ScanService {
  run(input: ScanInput): Promise<ScanResponse>;
  cancel(): boolean;
  dispose(): void;
}

export class ScanCancelledError extends Error {
  constructor() {
    super("Scan cancelled.");
    this.name = "ScanCancelledError";
  }
}
