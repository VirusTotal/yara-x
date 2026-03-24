import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import init, { Compiler } from "yara-x-wasm";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const wasmPath = path.join(projectRoot, "pkg", "yara-x-wasm_bg.wasm");

test("npm package self-import exposes the wasm API", async () => {
  const wasmBytes = await readFile(wasmPath);
  await init({ module_or_path: wasmBytes });

  const compiler = new Compiler();
  compiler.addSource("rule npm_ok { condition: false }");
  compiler.addSource(`
    rule npm_scan_ok {
      strings:
        $a = "abc"
      condition:
        $a
    }
  `);

  assert.deepEqual(compiler.errors, []);

  const rules = compiler.build();
  const scan = rules.scan(new Uint8Array([0x61, 0x62, 0x63]));
  assert.equal(scan.valid, true);
  assert.equal(scan.matches.length, 1);
  assert.equal(scan.matches[0].identifier, "npm_scan_ok");
});
