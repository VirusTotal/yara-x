# YARA-X Language Server Web Worker

Browser packaging for [`yara-x-ls`](../ls).

Exposes a `createWorker()` helper that starts the YARA-X language server
inside a dedicated web worker. The worker speaks standard LSP JSON-RPC over
`postMessage`, so it can be plugged into any browser-based LSP client.

Editor-agnostic, no dependency on Monaco or any specific UI.

## Build

From [`ls-wasm`](.) run:
```bash
npm run build:web
```

This generates the wasm-bindgen browser output in `pkg/`

## Usage
```js
import { createWorker } from "@virustotal/yara-x-ls-web";

const worker = await createWorker();
// Connect `worker` to your LSP client of choice.
// The worker speaks JSON-RPC over postMessage.
```

Internally, the Rust worker entry point adapts `postMessage` payloads to the
`Content-Length` framing expected by the language server core.
