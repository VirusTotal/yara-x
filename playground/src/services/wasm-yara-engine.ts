import initYara, {
  Compiler as WasmCompiler,
  Rules as WasmRules,
  Scanner as WasmScanner,
} from "@virustotal/yara-x";
import type {
  YaraCompiler,
  YaraEngine,
  YaraRules,
  YaraScanner,
} from "./yara-engine";

let initPromise: Promise<void> | undefined;

async function ensureInitialized() {
  initPromise ??= initYara().then(() => undefined);
  await initPromise;
}

function wrapScanner(scanner: WasmScanner): YaraScanner {
  return {
    setTimeoutMs: (timeoutMs) => scanner.setTimeoutMs(timeoutMs),
    setMaxMatchesPerPattern: (limit) => scanner.setMaxMatchesPerPattern(limit),
    setGlobal: (identifier, value) => scanner.setGlobal(identifier, value),
    scan: (payload) => scanner.scan(payload),
    dispose: () => scanner.free(),
  };
}

function wrapRules(rules: WasmRules): YaraRules {
  return {
    scan: (payload) => rules.scan(payload),
    scanner: () => wrapScanner(rules.scanner()),
    warnings: () => rules.warnings,
    dispose: () => rules.free(),
  };
}

function wrapCompiler(compiler: WasmCompiler): YaraCompiler {
  return {
    addSource: (source) => compiler.addSource(source),
    newNamespace: (namespace) => compiler.newNamespace(namespace),
    defineGlobal: (identifier, value) =>
      compiler.defineGlobal(identifier, value),
    errors: () => compiler.errors,
    warnings: () => compiler.warnings,
    build: () => wrapRules(compiler.build()),
    dispose: () => compiler.free(),
  };
}

export function getWasmYaraEngine(): YaraEngine {
  return {
    async createCompiler() {
      await ensureInitialized();
      return wrapCompiler(new WasmCompiler());
    },
  };
}
