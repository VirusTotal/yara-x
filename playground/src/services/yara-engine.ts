/**
 * Playground-facing contract for the browser engine integration.
 *
 * TODO(@kevinmuoz): Replace the local adapter with the official `yara-x-wasm`
 * npm package once PR #598 is merged and published.
 *
 * Expected upstream usage:
 *
 * import initYara, { Compiler, Scanner } from "yara-x-wasm";
 *
 * await initYara();
 *
 * const compiler = new Compiler();
 * compiler.addSource(rule);
 *
 * const rules = compiler.build();
 * const scanner = new Scanner(rules);
 * const result = scanner.scan(bytes);
 *
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
}

export interface YaraRules {
  scan(payload: Uint8Array): YaraEngineScanResult;
  scanner(): YaraScanner;
  warnings(): string[];
}

export interface YaraScanner {
  setTimeoutMs(timeoutMs: number): void;
  setMaxMatchesPerPattern(limit: number): void;
  setGlobal(identifier: string, value: unknown): void;
  scan(payload: Uint8Array): YaraEngineScanResult;
}
