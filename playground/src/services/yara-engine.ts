/**
 * Playground-facing contract for the browser engine integration.
 *
 * This contract intentionally mirrors the object-oriented browser API exposed
 * by the official `@virustotal/yara-x` package.
 */

export type YaraEngineScanResult = unknown;

export interface YaraEngine {
  createCompiler(): Promise<YaraCompiler>;
}

export interface YaraCompiler {
  addSource(source: string): void;
  newNamespace(namespace: string): void;
  defineGlobal(identifier: string, value: unknown): void;
  errors(): string[];
  warnings(): string[];
  build(): YaraRules;
  dispose(): void;
}

export interface YaraRules {
  scan(payload: Uint8Array): YaraEngineScanResult;
  scanner(): YaraScanner;
  warnings(): string[];
  dispose(): void;
}

export interface YaraScanner {
  setTimeoutMs(timeoutMs: number): void;
  setMaxMatchesPerPattern(limit: number): void;
  setGlobal(identifier: string, value: unknown): void;
  scan(payload: Uint8Array): YaraEngineScanResult;
  dispose(): void;
}
