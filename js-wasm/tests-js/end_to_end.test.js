import assert from "node:assert/strict";
import vm from "node:vm";
import test, { before } from "node:test";
import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const pkgDir = path.join(projectRoot, "pkg");
const distDir = path.join(projectRoot, "dist");
const jsEntrypoint = path.join(pkgDir, "yara_x_js.js");
const wasmPath = path.join(pkgDir, "yara_x_js_bg.wasm");

const {
  default: init,
  Compiler,
  Scanner,
} = await import(
  pathToFileURL(jsEntrypoint).href
);

before(async () => {
  const wasmBytes = await readFile(wasmPath);
  await init({ module_or_path: wasmBytes });
});

function asRuleSources(ruleSources) {
  return Array.isArray(ruleSources) ? ruleSources : [ruleSources];
}

function validateWithCompilerApi(api, ruleSources) {
  const compiler = new api.Compiler();
  for (const source of asRuleSources(ruleSources)) {
    compiler.addSource(source);
  }
  return {
    valid: compiler.errors.length === 0,
    errors: compiler.errors,
    warnings: compiler.warnings,
  };
}

function scanWithCompilerApi(api, ruleSources, payload) {
  const compiler = new api.Compiler();
  for (const source of asRuleSources(ruleSources)) {
    compiler.addSource(source);
  }
  const rules = compiler.build();
  return rules.scan(payload);
}

const packageApi = { Compiler };

function findByIdentifier(items, identifier) {
  return items.find((item) => item.identifier === identifier);
}

function bytesToArray(value) {
  if (value instanceof Uint8Array) {
    return Array.from(value);
  }
  if (Array.isArray(value)) {
    return value;
  }
  return [];
}

async function loadBundleApi(bundlePath) {
  const [bundleSource, wasmBytes] = await Promise.all([
    readFile(bundlePath, "utf8"),
    readFile(wasmPath),
  ]);

  const context = {
    console,
    WebAssembly,
    TextDecoder,
    TextEncoder,
    Uint8Array,
    ArrayBuffer,
    DataView,
    URL,
    Request,
    Response,
    fetch,
    performance,
    module: { exports: {} },
  };
  context.globalThis = context;
  context.self = context;
  context.window = context;

  vm.runInNewContext(bundleSource, context, { filename: bundlePath });

  assert.ok(
    context.YaraWasm,
    `${path.basename(bundlePath)} should expose a YaraWasm global`,
  );
  assert.equal(
    context.YaraWasm,
    context.module.exports,
    `${path.basename(bundlePath)} should keep the CommonJS export in sync`,
  );

  context.__wasmBytes = wasmBytes;
  const initOptions = vm.runInNewContext(
    "({ module_or_path: __wasmBytes })",
    context,
  );
  await context.YaraWasm(initOptions);
  delete context.__wasmBytes;
  return context.YaraWasm;
}

test("Compiler accepts a single rule source", () => {
  const rule = `
    rule single_ok {
      strings:
        $a = "abc"
      condition:
        $a
    }
  `;

  const result = validateWithCompilerApi(packageApi, rule);
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("Compiler accepts the full browser module set", () => {
  const moduleRules = [
    "console",
    "crx",
    "dex",
    "dotnet",
    "elf",
    "hash",
    "lnk",
    "macho",
    "math",
    "pe",
    "string",
    "time",
    "test_proto2",
    "test_proto3",
  ].map(
    (moduleName) => `
      import "${moduleName}"
      rule ${moduleName.replace(/[^a-z0-9]/gi, "_")}_module_available {
        condition:
          true
      }
    `,
  );

  const result = validateWithCompilerApi(packageApi, moduleRules);
  assert.equal(result.valid, true, result.errors.join("\n"));
  assert.deepEqual(result.errors, []);
});

test("Compiler.build rejects accumulated compile errors", () => {
  const compiler = new Compiler();

  assert.throws(
    () => compiler.addSource("rule bad { condition: and }"),
    /syntax error/i,
  );
  assert.ok(compiler.errors.length > 0);
  assert.throws(() => compiler.build(), /syntax error/i);
});

test("Rules.scan supports the browser-backed time module end to end", () => {
  const result = scanWithCompilerApi(
    packageApi,
    `
      import "time"
      rule time_module_works {
        condition:
          time.now() > 1600000000
      }
    `,
    new Uint8Array(),
  );

  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 1);
  assert.equal(result.matches[0].identifier, "time_module_works");
});

test("Rules.scan and Scanner.scan preserve compiler warnings", () => {
  const compiler = new Compiler();
  compiler.addSource(`
    rule slow_loop_warning {
      condition:
        for any i in (0..filesize) : ( true )
    }
  `);

  assert.ok(
    compiler.warnings.some((warning) => /potentially slow loop/i.test(warning)),
  );

  const rules = compiler.build();
  const expectedWarnings = rules.warnings;

  const rulesScan = rules.scan(new Uint8Array());
  assert.deepEqual(rulesScan.warnings, expectedWarnings);

  const scanner = rules.scanner();
  const scannerScan = scanner.scan(new Uint8Array());
  assert.deepEqual(scannerScan.warnings, expectedWarnings);
});


test("Compiler accepts a list of rule sources", () => {
  const rules = [
    "rule first_ok { condition: true }",
    "rule second_ok { condition: 1 == 1 }",
  ];

  const result = validateWithCompilerApi(packageApi, rules);
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("Rules.scan returns no matches when nothing matches", () => {
  const rule = `
    rule no_match {
      strings:
        $a = "abc"
      condition:
        $a
    }
  `;

  const result = scanWithCompilerApi(
    packageApi,
    rule,
    new Uint8Array([0x78, 0x79, 0x7a]),
  );
  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 0);
});

test("Compiler accepts multiple rule sources and only matching rules fire", () => {
  const rules = [
    `
      rule should_match {
        strings:
          $a = "abc"
        condition:
          $a
      }
    `,
    `
      rule should_not_match {
        strings:
          $b = "zzz"
        condition:
          $b
      }
    `,
  ];

  const result = scanWithCompilerApi(
    packageApi,
    rules,
    new Uint8Array([0x61, 0x62, 0x63]),
  );
  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 1);
  assert.equal(result.matches[0].identifier, "should_match");
});

test("Rules.scan returns multiple matches from multiple rules in a single source", () => {
  const rules = `
    rule hit_one {
      strings:
        $a = "abc"
      condition:
        $a
    }

    rule hit_two {
      strings:
        $b = "def"
      condition:
        $b
    }
  `;

  const payload = new Uint8Array([
    0x7a, 0x7a, 0x61, 0x62, 0x63, 0x7a, 0x64, 0x65, 0x66, 0x7a,
  ]);
  const result = scanWithCompilerApi(packageApi, rules, payload);

  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 2);
  assert.deepEqual(
    result.matches.map((m) => m.identifier).sort(),
    ["hit_one", "hit_two"],
  );
});

test("Rules.scan returns multiple matches from multiple rule sources", () => {
  const rules = [
    `
      rule arr_hit_one {
        strings:
          $a = "abc"
        condition:
          $a
      }
    `,
    `
      rule arr_hit_two {
        strings:
          $b = "abc"
        condition:
          $b
      }
    `,
  ];

  const result = scanWithCompilerApi(
    packageApi,
    rules,
    new Uint8Array([0x61, 0x62, 0x63]),
  );
  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 2);
  assert.deepEqual(
    result.matches.map((m) => m.identifier).sort(),
    ["arr_hit_one", "arr_hit_two"],
  );
});

test("Rules.scan returns match details, tags, and metadata values", () => {
  const rules = `
    private rule private_example : one two {
      meta:
        int_meta = 7
        float_meta = 3.5
        bool_meta = true
        str_meta = "hello"
        bytes_meta = "A\\x00B"
      strings:
        $a = "abc"
        $private_string = "bc" private
      condition:
        $a and $private_string
    }
  `;

  const payload = new Uint8Array([0x7a, 0x7a, 0x61, 0x62, 0x63, 0x7a]);
  const result = scanWithCompilerApi(packageApi, rules, payload);

  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 1);

  const matchedRule = result.matches[0];
  assert.equal(matchedRule.identifier, "private_example");
  assert.equal(matchedRule.namespace, "default");
  assert.equal(matchedRule.isPrivate, true);
  assert.equal(matchedRule.isGlobal, false);
  assert.deepEqual(matchedRule.tags, ["one", "two"]);

  const intMeta = findByIdentifier(matchedRule.metadata, "int_meta");
  const floatMeta = findByIdentifier(matchedRule.metadata, "float_meta");
  const boolMeta = findByIdentifier(matchedRule.metadata, "bool_meta");
  const strMeta = findByIdentifier(matchedRule.metadata, "str_meta");
  const bytesMeta = findByIdentifier(matchedRule.metadata, "bytes_meta");

  assert.equal(intMeta.value, 7);
  assert.equal(floatMeta.value, 3.5);
  assert.equal(boolMeta.value, true);
  assert.equal(strMeta.value, "hello");
  assert.deepEqual(bytesToArray(bytesMeta.value), [0x41, 0x00, 0x42]);

  const patternA = findByIdentifier(matchedRule.patterns, "$a");
  const privatePattern = findByIdentifier(matchedRule.patterns, "$private_string");

  assert.equal(patternA.kind, "text");
  assert.equal(patternA.isPrivate, false);
  assert.equal(patternA.matches.length, 1);
  assert.equal(patternA.matches[0].offset, 2);
  assert.equal(patternA.matches[0].length, 3);
  assert.deepEqual(bytesToArray(patternA.matches[0].data), [0x61, 0x62, 0x63]);

  assert.equal(privatePattern.isPrivate, true);
  assert.equal(privatePattern.matches.length, 1);
});

test("hash module functions work in rule conditions", () => {
  const rules = `
    import "hash"

    rule hash_module_ok {
      condition:
        hash.md5(0, filesize) == "6df23dc03f9b54cc38a0fc1483df6e21" and
        hash.sha1(0, filesize) == "5f5513f8822fdbe5145af33b64d8d970dcf95c6e" and
        hash.sha256(0, filesize) == "97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d" and
        hash.crc32(0, filesize) == 0x1a7827aa and
        hash.checksum32(0, filesize) == 950 and
        hash.md5(3, 3) == hash.md5("bar")
    }
  `;

  const result = scanWithCompilerApi(
    packageApi,
    rules,
    new TextEncoder().encode("foobarbaz"),
  );
  assert.equal(result.valid, true);
  assert.deepEqual(result.matches.map((m) => m.identifier), ["hash_module_ok"]);
});

test("math module functions work in rule conditions", () => {
  const rules = `
    import "math"

    rule math_module_ok {
      condition:
        math.min(1, 2) == 1 and
        math.max(1, 2) == 2 and
        math.abs(-7) == 7 and
        math.in_range(0.5, 0.0, 1.0) and
        math.count(0x41, 0, 5) == 4 and
        math.percentage(0x41, 0, 5) > 0.79 and
        math.percentage(0x41, 0, 5) < 0.81 and
        math.mode(0, 5) == 0x41 and
        math.to_string(32, 16) == "20" and
        math.to_number(true) == 1
    }
  `;

  const result = scanWithCompilerApi(
    packageApi,
    rules,
    new TextEncoder().encode("AAAAB"),
  );
  assert.equal(result.valid, true);
  assert.deepEqual(result.matches.map((m) => m.identifier), ["math_module_ok"]);
});

test("string module functions work in rule conditions", () => {
  const rules = `
    import "string"

    rule string_module_ok {
      condition:
        string.length("AXsx00ERS") == 9 and
        string.to_int("1234") == 1234 and
        string.to_int("-011", 8) == -9 and
        string.to_int("A", 16) == 10
    }
  `;

  const result = scanWithCompilerApi(
    packageApi,
    rules,
    new Uint8Array([0x00]),
  );
  assert.equal(result.valid, true);
  assert.deepEqual(result.matches.map((m) => m.identifier), ["string_module_ok"]);
});

test("Compiler/Rules/Scanner object API scans end to end", () => {
  const compiler = new Compiler();
  compiler.addSource(`
    rule obj_hit_one {
      strings:
        $a = "abc"
      condition:
        $a
    }
  `);
  compiler.addSource(`
    rule obj_hit_two {
      strings:
        $b = "def"
      condition:
        $b
    }
  `);

  assert.deepEqual(compiler.errors, []);
  const rules = compiler.build();
  assert.ok(rules);
  assert.ok(Array.isArray(rules.warnings));

  const payload = new Uint8Array([
    0x61, 0x62, 0x63, 0x20, 0x64, 0x65, 0x66,
  ]);

  const viaRules = rules.scan(payload);
  assert.equal(viaRules.valid, true);
  assert.deepEqual(
    viaRules.matches.map((m) => m.identifier).sort(),
    ["obj_hit_one", "obj_hit_two"],
  );

  const scanner = new Scanner(rules);
  scanner.setMaxMatchesPerPattern(10);
  scanner.setTimeoutMs(250);
  const viaScanner = scanner.scan(payload);

  assert.equal(viaScanner.valid, true);
  assert.deepEqual(
    viaScanner.matches.map((m) => m.identifier).sort(),
    ["obj_hit_one", "obj_hit_two"],
  );
});

test("Compiler.newNamespace keeps rule namespaces in the built package", () => {
  const compiler = new Compiler();
  compiler.newNamespace("alpha");
  compiler.addSource("rule first { condition: true }");
  compiler.newNamespace("beta");
  compiler.addSource("rule second { condition: true }");

  const result = compiler.build().scan(new Uint8Array([0x00]));
  assert.equal(result.valid, true);
  assert.deepEqual(
    result.matches.map((m) => `${m.namespace}:${m.identifier}`).sort(),
    ["alpha:first", "beta:second"],
  );
});

test("Scanner.setMaxMatchesPerPattern limits match details end to end", () => {
  const compiler = new Compiler();
  compiler.addSource(`
    rule limited {
      strings:
        $a = "aa"
      condition:
        $a
    }
  `);

  const rules = compiler.build();
  const scanner = new Scanner(rules);
  const payload = new TextEncoder().encode("aaaaaa");
  const baseline = rules.scan(payload);
  assert.equal(baseline.valid, true);
  assert.ok(baseline.matches[0].patterns[0].matches.length > 1);

  scanner.setMaxMatchesPerPattern(1);
  const limited = scanner.scan(payload);
  assert.equal(limited.valid, true);
  assert.equal(limited.matches.length, 1);
  assert.equal(limited.matches[0].patterns[0].matches.length, 1);
});

test("external globals can be defined and overridden per scanner", () => {
  const compiler = new Compiler();
  compiler.defineGlobal("ext_enabled", false);
  compiler.defineGlobal("ext_count", 0);
  compiler.defineGlobal("ext_name", "unset");
  compiler.addSource(`
    rule uses_external_globals {
      condition:
        ext_enabled and ext_count == 7 and ext_name == "prod"
    }
  `);

  const rules = compiler.build();
  const scanner = new Scanner(rules);

  const defaultResult = scanner.scan(new Uint8Array([0x00]));
  assert.equal(defaultResult.valid, true);
  assert.deepEqual(defaultResult.matches, []);

  scanner.setGlobal("ext_enabled", true);
  scanner.setGlobal("ext_count", 7);
  scanner.setGlobal("ext_name", "prod");

  const matchResult = scanner.scan(new Uint8Array([0x00]));
  assert.equal(matchResult.valid, true);
  assert.equal(matchResult.matches.length, 1);
  assert.equal(matchResult.matches[0].identifier, "uses_external_globals");

  scanner.setGlobal("ext_count", 8);
  const mismatchResult = scanner.scan(new Uint8Array([0x00]));
  assert.equal(mismatchResult.valid, true);
  assert.deepEqual(mismatchResult.matches, []);
});

test("compiler-built rules keep per-scanner globals isolated across reused scanners", () => {
  const compiler = new Compiler();
  compiler.defineGlobal("tenant", "unset");
  compiler.addSource(`
    rule tenant_a {
      condition:
        tenant == "a"
    }
  `);
  compiler.addSource(`
    rule tenant_b {
      condition:
        tenant == "b"
    }
  `);

  const rules = compiler.build();
  const scannerA = new Scanner(rules);
  const scannerB = new Scanner(rules);

  scannerA.setGlobal("tenant", "a");
  scannerB.setGlobal("tenant", "b");

  for (let round = 0; round < 5; round += 1) {
    const aResult = scannerA.scan(new Uint8Array([0x00]));
    const bResult = scannerB.scan(new Uint8Array([0x00]));

    assert.equal(aResult.valid, true);
    assert.deepEqual(
      aResult.matches.map((m) => m.identifier),
      ["tenant_a"],
      `scanner A should keep its globals in round ${round}`,
    );

    assert.equal(bResult.valid, true);
    assert.deepEqual(
      bResult.matches.map((m) => m.identifier),
      ["tenant_b"],
      `scanner B should keep its globals in round ${round}`,
    );
  }

  scannerA.setGlobal("tenant", "b");
  const flippedResult = scannerA.scan(new Uint8Array([0x00]));
  assert.equal(flippedResult.valid, true);
  assert.deepEqual(
    flippedResult.matches.map((m) => m.identifier),
    ["tenant_b"],
  );

  const unaffectedResult = scannerB.scan(new Uint8Array([0x00]));
  assert.equal(unaffectedResult.valid, true);
  assert.deepEqual(
    unaffectedResult.matches.map((m) => m.identifier),
    ["tenant_b"],
  );
});

test("Scanner.setGlobal rejects undefined globals", () => {
  const compiler = new Compiler();
  compiler.addSource("rule always_true { condition: true }");
  const scanner = compiler.build().scanner();

  assert.throws(
    () => scanner.setGlobal("not_defined", true),
    /not defined/i,
  );
});

test("Scanner.setGlobal rejects type mismatches", () => {
  const compiler = new Compiler();
  compiler.defineGlobal("ext_bool", false);
  compiler.addSource("rule check_bool { condition: ext_bool }");
  const scanner = compiler.build().scanner();

  assert.throws(
    () => scanner.setGlobal("ext_bool", 1),
    /invalid type/i,
  );
});

test("Rules.scanner() creates a scanner object", () => {
  const compiler = new Compiler();
  compiler.addSource("rule scoped { condition: true }");
  const rules = compiler.build();
  const scanner = rules.scanner();
  const result = scanner.scan(new Uint8Array([0x00]));
  assert.equal(result.valid, true);
  assert.equal(result.matches.length, 1);
  assert.equal(result.matches[0].identifier, "scoped");
});

test("Compiler + Rules stay correct across repeated compile+scan rounds", () => {
  const rounds = 40;

  for (let i = 0; i < rounds; i += 1) {
    const ruleName = `round_${i}_rule`;
    const needle = `marker_${i}_abcdef`;
    const rules = `
      rule ${ruleName} {
        strings:
          $a = "${needle}"
        condition:
          $a
      }
    `;

    const payload = new TextEncoder().encode(`xx${needle}yy`);
    const result = scanWithCompilerApi(packageApi, rules, payload);

    assert.equal(result.valid, true, `round ${i} should compile and scan`);
    assert.equal(
      result.matches.length,
      1,
      `round ${i} should only report one match`,
    );
    assert.equal(result.matches[0].identifier, ruleName);
  }
});

test("Scanner reuse does not retain stale match state across scans", () => {
  const compiler = new Compiler();
  compiler.addSource(`
    rule alpha_hit {
      strings:
        $a = "alpha"
      condition:
        $a
    }
  `);
  compiler.addSource(`
    rule beta_hit {
      strings:
        $b = "beta"
      condition:
        $b
    }
  `);

  const rules = compiler.build();
  const scanner = rules.scanner();

  const scenarios = [
    {
      payload: new TextEncoder().encode("prefix alpha suffix"),
      expected: ["alpha_hit"],
    },
    {
      payload: new TextEncoder().encode("no markers here"),
      expected: [],
    },
    {
      payload: new TextEncoder().encode("prefix beta suffix"),
      expected: ["beta_hit"],
    },
    {
      payload: new TextEncoder().encode("alpha and beta"),
      expected: ["alpha_hit", "beta_hit"],
    },
    {
      payload: new TextEncoder().encode("still no markers"),
      expected: [],
    },
  ];

  for (const { payload, expected } of scenarios) {
    const result = scanner.scan(payload);
    assert.equal(result.valid, true);
    assert.deepEqual(
      result.matches.map((m) => m.identifier).sort(),
      [...expected].sort(),
    );
  }
});

test("Compiler/Rules/Scanner cycles stay isolated across rounds", () => {
  const rounds = 25;

  for (let i = 0; i < rounds; i += 1) {
    const compiler = new Compiler();
    const hitName = `cycle_hit_${i}`;
    const missName = `cycle_miss_${i}`;
    const marker = `hit-marker-${i}`;

    compiler.addSource(`
      rule ${hitName} {
        strings:
          $a = "${marker}"
        condition:
          $a
      }
    `);
    compiler.addSource(`
      rule ${missName} {
        strings:
          $b = "never-${i}"
        condition:
          $b
      }
    `);

    const rules = compiler.build();
    const scanner = new Scanner(rules);

    const hitPayload = new TextEncoder().encode(`xx ${marker} yy`);
    const hitResult = scanner.scan(hitPayload);
    assert.equal(hitResult.valid, true);
    assert.deepEqual(
      hitResult.matches.map((m) => m.identifier),
      [hitName],
      `round ${i} should not receive matches from other rounds`,
    );

    const missResult = scanner.scan(new TextEncoder().encode("plain payload"));
    assert.equal(missResult.valid, true);
    assert.deepEqual(
      missResult.matches,
      [],
      `round ${i} second scan should not retain prior match results`,
    );
  }
});

test("Compiler exposes errors/warnings and only becomes consumed after a successful build()", () => {
  const failingCompiler = new Compiler();
  assert.throws(
    () => failingCompiler.addSource("rule bad { condition: and }"),
    /error/i,
  );
  assert.ok(failingCompiler.errors.length > 0);
  assert.throws(() => failingCompiler.build(), /syntax error/i);

  const compiler = new Compiler();
  compiler.addSource("rule after_build { condition: true }");
  const rules = compiler.build();
  assert.ok(rules);

  assert.throws(
    () => compiler.addSource("rule after_successful_build { condition: true }"),
    /compiler has already been consumed/,
  );
});

test("Compiler.addSource surfaces include loading errors clearly", () => {
  const compiler = new Compiler();
  assert.throws(
    () => {
      compiler.addSource(`
        include "missing.yar"
        rule include_compiler_test {
          condition:
            true
        }
      `);
    },
    /error including file/i,
  );
});
