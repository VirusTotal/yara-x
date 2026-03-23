import type { YaraCompiler, YaraEngine } from "./yara-engine";

function notImplemented(message: string): never {
  throw new Error(message);
}

function compilerTodo(): YaraCompiler {
  return {
    addSource: (_source) => {
      notImplemented(
        `TODO(@kevinmuoz): wire "Compiler.addSource" to the official "yara-x-wasm" npm package once PR #598 is merged and published.`,
      );
    },
    newNamespace: (_namespace) => {
      notImplemented(
        `TODO(@kevinmuoz): wire "Compiler.newNamespace" to the official "yara-x-wasm" npm package once PR #598 is merged and published.`,
      );
    },
    defineGlobal: (_identifier, _value) => {
      notImplemented(
        `TODO(@kevinmuoz): wire "Compiler.defineGlobal" to the official "yara-x-wasm" npm package once PR #598 is merged and published.`,
      );
    },
    errors: () => {
      notImplemented(
        `TODO(@kevinmuoz): expose "Compiler.errors()" from the official "yara-x-wasm" npm package once PR #598 is merged and published.`,
      );
    },
    warnings: () => {
      notImplemented(
        `TODO(@kevinmuoz): expose "Compiler.warnings()" from the official "yara-x-wasm" npm package once PR #598 is merged and published.`,
      );
    },
    build: () => {
      notImplemented(
        `TODO(@kevinmuoz): wire "Compiler.build()" to the official "yara-x-wasm" npm package once PR #598 is merged and published.`,
      );
    },
  };
}

export function getWasmYaraEngine(): YaraEngine {
  return {
    async createCompiler() {
      /**
       * TODO(@kevinmuoz): I'll Replace this local placeholder with an adapter around
       * the upstream `yara-x-wasm` npm package once PR #598 lands
       *
       * Possible future config:
       *
       * import initYara, { Compiler } from "yara-x-wasm";
       *
       * await initYara();
       * const compiler = new Compiler();
       *
       */
      return compilerTodo();
    },
  };
}
