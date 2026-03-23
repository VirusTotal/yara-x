# YARA-X Playground

This folder contains the browser playground for YARA-X. The goal of the
playground is to provide a lightweight web interface for writing, formatting,
and eventually testing YARA rules directly in the browser.

The current version is `0.0.0`. At this stage, the focus is on establishing the
front-end foundation of the playground:

- TypeScript for the application code
- Lit for the UI
- Vite for development and builds
- Monaco-based editor integration for the rule and sample panes

This version is intentionally limited. It is expected to compile and provide
the basic UI structure, but it is not expected to be fully functional end to
end yet.

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

## Project status

At the moment, this folder contains:

- the application shell and layout
- the editor setup
- the styling and interaction base
- the first browser-facing service contracts for the engine and the language
  server

What is still missing:

- a working browser engine integration
- a working browser language server integration
- the final packaging strategy for browser artifacts
- deployment workflows

The intention is to connect those pieces once the browser packages are ready
and their public interfaces are stable.
