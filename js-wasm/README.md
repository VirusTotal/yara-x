# yara-wasm

Browser-focused WebAssembly packaging for [`yara-x`](../lib) with the existing
`yara-wasm` JavaScript API preserved.

## Package surface

- `validateRules(rules)`
- `scanRules(rules, payload)`
- `Compiler`, `Rules`, and `Scanner`

`rules` accepts either a single rule string or an array of rule strings.
`payload` accepts a `Uint8Array` or any value accepted by wasm-bindgen as
`&[u8]`.

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

- `pkg/yara_wasm.js`
- `pkg/yara_wasm_bg.wasm`
- `dist/yara_wasm_bundle.js`
- `dist/yara_wasm_bundle.min.js`

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

```js
import init, { validateRules, scanRules } from "yara-wasm";

await init();

const validation = validateRules('rule ok { condition: true }');
const result = scanRules(
  'rule x { strings: $a = "abc" condition: $a }',
  new Uint8Array([0x61, 0x62, 0x63]),
);
```

Object-style API:

```js
import init, { Compiler, Scanner } from "yara-wasm";

await init();

const compiler = new Compiler();
compiler.defineGlobal("threshold", 7);
compiler.addSource('rule x { condition: threshold == 7 }');

const rules = compiler.build();
const scanner = new Scanner(rules);
scanner.setGlobal("threshold", 9);
```
