# yara-x-wasm

Browser-focused WebAssembly packaging for [`yara-x`](../lib) with an
object-oriented JavaScript API built around `Compiler`, `Rules`, and
`Scanner`.

## Package surface

- `Compiler`, `Rules`, and `Scanner`

## Build

From [`js-wasm`](.) run:

```bash
cargo install --locked wasm-pack --version 0.14.0
cargo install --locked wasm-bindgen-cli --version 0.2.113
wasm-pack build --target web --release --mode no-install --no-pack
```

This produces the standard browser package in `pkg/`.

For the full package layout, including the preserved no-modules bundles in
`dist/`:

```bash
cargo run --release --features release-tools --bin build_web_release --
```

or:

```bash
cargo build-web-release
```

This produces:

- `pkg/yara-x-wasm.js`
- `pkg/yara-x-wasm_bg.wasm`
- `dist/yara-x-wasm-bundle.js`
- `dist/yara-x-wasm-bundle.min.js`

The no-modules bundle reuses the shared `pkg/yara-x-wasm_bg.wasm` binary
instead of shipping a second copy under `dist/`.

SIMD is enabled for `wasm32-unknown-unknown` via `js-wasm/.cargo/config.toml`.

## Tests

Rust/browser API coverage:

```bash
npm run test:wasm-node
```

Headless browser coverage for browser-specific behavior such as console output:

```bash
CHROME_BIN=/path/to/chrome \
CHROMEDRIVER=/path/to/chromedriver \
npm run test:wasm-browser
```

JS end-to-end coverage against the generated `pkg/` + `dist/` outputs:

```bash
npm run test:js
```

Package validation:

```bash
npm run pack:dry-run
```

## Usage

### ES module usage:

```js
import init, { Compiler } from "yara-x-wasm";

await init();

const compiler = new Compiler();
compiler.addSource('rule x { strings: $a = "abc" condition: $a }');

const rules = compiler.build();
const result = rules.scan(new Uint8Array([0x61, 0x62, 0x63]));
```

### No-modules bundle usage:

```html
<script src="./dist/yara-x-wasm-bundle.js"></script>
<script>
  (async () => {
    await YaraWasm();

    const compiler = new YaraWasm.Compiler();
    compiler.addSource('rule x { strings: $a = "abc" condition: $a }');

    const rules = compiler.build();
    const result = rules.scan(new Uint8Array([0x61, 0x62, 0x63]));

    console.log(result.matches);
  })();
</script>
```

Use `dist/yara-x-wasm-bundle.min.js` instead of `dist/yara-x-wasm-bundle.js` for
production deployments. By default the bundle loads its wasm from
`pkg/yara-x-wasm_bg.wasm`, so keep the standard package layout intact when
serving it.

### Object-style API with scanner configuration:

```js
import init, { Compiler, Scanner } from "yara-x-wasm";

await init();

const compiler = new Compiler();
compiler.defineGlobal("threshold", 7);
compiler.addSource('rule x { condition: threshold == 7 }');

const rules = compiler.build();
const scanner = new Scanner(rules);
scanner.setGlobal("threshold", 9);
```
