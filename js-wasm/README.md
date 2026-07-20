# @virustotal/yara-x

JavaScript bindings for [YARA-X](https://github.com/VirusTotal/yara-x) using WebAssembly.

## Installation

```bash
npm install @virustotal/yara-x
```

## Quick Start

```js
import init, { Compiler } from "@virustotal/yara-x";

// Initialize the WebAssembly module
await init();

// Compile a rule
const compiler = new Compiler();
compiler.addSource('rule test { strings: $a = "abc" condition: $a }');

const rules = compiler.build();

// Scan data
const payload = new Uint8Array([0x61, 0x62, 0x63, 0x64]); // "abcd"
const result = rules.scan(payload);

if (result.valid && result.matches.length > 0) {
  console.log("Rule matched!");
}
```

## API Reference

### `Compiler`

The `Compiler` translates YARA-X rules into a executable format.

- `addSource(source: string)`: Compiles a rule string. Throws an error if compilation fails.
- `build(): Rules`: Finalizes compilation and returns a `Rules` object.
- `defineGlobal(identifier: string, value: any)`: Defines an external variable used in conditions (boolean, number, string).
- `newNamespace(namespace: string)`: Scopes subsequent rules to a specific namespace.
- `errors: string[]`: Array of compilation error messages.
- `warnings: string[]`: Array of compilation warning messages.

### `Rules`

The `Rules` object represents the compiled set of rules ready for scanning.

- `scan(payload: Uint8Array): ScanResult`: Scans the payload using the default scanner profile.
- `scanner(): Scanner`: Spawns a dedicated `Scanner` for advanced configuration.
- `warnings: string[]`: Warnings inherited from the compiler.

### `Scanner`

The `Scanner` provides fine-grained control over scanning operations.

- `scan(payload: Uint8Array): ScanResult`: Scans the payload.
- `setGlobal(identifier: string, value: any)`: Overrides values defined by `compiler.defineGlobal()`.
- `setMaxMatchesPerPattern(n: number)`: Limits reporting to first `n` matches per pattern.
- `setTimeoutMs(timeout_ms: number)`: Sets a hard timeout for scanning.

---

## Scan Results Structure

The `.scan(...)` methods return an object detailing matches and diagnostics:

```json
{
  "valid": true,
  "matches": [
    {
      "identifier": "rule_name",
      "namespace": "default",
      "isPrivate": false,
      "isGlobal": false,
      "tags": ["tag_a"],
      "metadata": [
        { "identifier": "key", "value": "value" }
      ],
      "patterns": [
        {
          "identifier": "$a",
          "kind": "text",
          "isPrivate": false,
          "matches": [
            { "offset": 2, "length": 3 }
          ]
        }
      ]
    }
  ],
  "warnings": []
}
```

---

## Resource Management

Objects generated in WebAssembly live in the Wasm heap, which is separate from the JavaScript garbage-collected 
heap. If you do not manually free these objects, they will leak memory in the WebAssembly space.

Ensure you call `.free()` on objects when no longer needed:

```js
const compiler = new Compiler();
try {
  compiler.addSource('rule x { condition: true }');
  const rules = compiler.build();
  const payload = new Uint8Array([0x00]); // Self-contained payload
  rules.scan(payload);
  rules.free();
} finally {
  compiler.free();
}
```

### Modern JavaScript (Explicit Resource Management)

If your environment supports the new JavaScript `using` keyword (Explicit Resource Management), you can let the 
runtime handle it automatically because the types implement `[Symbol.dispose]`:

```js
{
  using compiler = new Compiler();
  compiler.addSource('rule x { condition: true }');
} // compiler.free() is called automatically here!
```

