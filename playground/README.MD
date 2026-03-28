# YARA-X Playground

This folder contains the browser playground for YARA-X.

The playground provides a web interface for writing, formatting, and testing
YARA rules directly in the browser. It uses the official `@virustotal/yara-x`
package for the scanning engine and runs the YARA-X language server inside a
dedicated web worker for editor features.

## Requirements

- Node `22.22.1`
- `pnpm`

The Node version is pinned in [`.nvmrc`](./.nvmrc).

## Getting started

```bash
nvm use
pnpm install
pnpm dev
```

This starts the Vite development server. Open the local URL printed in the
terminal.

## Scripts

```bash
pnpm dev
pnpm build
pnpm preview
pnpm format
```
