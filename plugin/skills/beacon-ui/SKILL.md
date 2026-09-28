---
name: beacon-ui
description: Start the Python Beacon TUI or loopback GUI, or the separate assurance workspace server. The UI adds no assurance.
---

# Beacon UI

Use this skill to open a local screen. Pick one surface.

## Python engine

`beacon serve` and `beacon tui` call the same collect, check, and push functions as the CLI. They add no assurance. The walkthrough does not collect, check, or push.

```bash
beacon serve
beacon tui
beacon tui --no-tour
```

`beacon serve` binds `127.0.0.1` port `8080` unless you pass `--host` and `--port`. Screens are Dashboard, Assessment, Freshness, Validation, Push, and System.

`beacon tui` uses a dark navy theme. The first launch opens a walkthrough. Press `?` or `h`, or the Tour button, to open it again. `h` types into a focused field. `?` still opens the tour. Skip and Done write `.beacon/tui_tour_seen`. `BEACON_NO_TOUR=1` skips the auto-start and does not write that flag.

A non-loopback bind needs `BEACON_API_TOKEN`. Read the Interfaces section of `docs/VERIFIED_WORKFLOW.md` before you change the bind.

## Assurance workspace

This server is the Node app in `assurance/`. It does not use `.beacon/keys`.

```bash
cd assurance
npm ci
npx vite build --config portable/vite.config.ts
node portable/server.mjs
```

Node 24 or later is required. The server binds loopback port `8787`. Set `BEACON_TOKENS_JSON` and `BEACON_DATABASE` outside the repo. A token needs at least 32 characters. Do not commit a token.

`/product` is the product page. `/trust` is the sandbox trust center. Imports stay unverified. Reports stay drafts.

`node portable/mcp.mjs` starts MCP on stdio. Stdio stays read-only unless `BEACON_MCP_WRITES=true`.

## Success

The process listens on loopback. You can open the page or the TUI. You still use `beacon check` or the assurance tests for a custody result.

## Stop

Stop when you would bind a public address without a token and TLS. Keep the default loopback bind.

Stop when you would store `BEACON_TOKENS_JSON` or `BEACON_API_TOKEN` in a file in git.

Stop when a screen looks green and you want a claim word. Use `beacon-custody-claims`.
