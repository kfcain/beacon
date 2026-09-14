# Sources

Beacon uses public GRC engineering work as **shape references**. This repository does not vendor those codebases.

## GRC Engineering Club inspectors

- Org: [GRCEngClub](https://github.com/GRCEngClub)
- Toolkit: [GRCEngClub/claude-grc-engineering](https://github.com/GRCEngClub/claude-grc-engineering)
- Connectors used as the inspector shape: `plugins/connectors/aws-inspector`, `azure-inspector`, `gcp-inspector`
- Collect contract: CLI-backed probes (`aws` / `az` / `gcloud`), SCF-tagged findings (IAC-01, CRY-05, and related checks), fixture-friendly first run

Beacon's `CloudInspectorPlugin` follows that connector outline (probe identity, collect a small IAM + encryption surface, emit SCF-tagged findings). It does not copy the Node collect scripts.

## Paramify fetchers

- Upstream: [paramify/paramify-fetchers](https://github.com/paramify/paramify-fetchers)
- Fork reference: [kfcain/paramify-fetchers](https://github.com/kfcain/paramify-fetchers)
- Shapes used: `Fetcher` / category `PlatformSpec`, `collect()` runner, evidence envelope, and the TUI workspace (catalog / run / evidence / upload)

Beacon's `FetcherSpec`, drop-in `PLUGIN` loader, TUI tabs (Dashboard, Freshness, Validation, Push, System, Collect), and GUI pages follow that operator flow. Fetcher catalogs are not vendored.

## SCF hub

- Pin: SCF **2026.2** offline bundle (`beacon/scf/offline/`, [docs/SCF.md](SCF.md))
- Workbook SHA-256: `9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835`
- Counts: 1534 controls, 34 families, 316 ERLs, 249 mapped crosswalk frameworks
- Live API (not the pin): [https://hackidle.github.io/scf-api/](https://hackidle.github.io/scf-api/) (2026.1.1)
- Club API (not the pin): [GRCEngClub/scf-api](https://github.com/GRCEngClub/scf-api) (2026.1)
- License: CC BY-ND
- Offline bundle: `IAC-01`, `CRY-05`, Quantum Security `QTS-*`, and ERL slice `E-QTS-01` … `E-QTS-13` for `BEACON_SCF_OFFLINE=1`
