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

- API: [https://hackidle.github.io/scf-api/](https://hackidle.github.io/scf-api/)
- Project: [hackIDLE/scf-api](https://github.com/hackIDLE/scf-api)
- Version: SCF 2026.1.1 (CC BY-ND)
- Offline bundle: verbatim `IAC-01` and `CRY-05` control JSON plus a compact summary, for `BEACON_SCF_OFFLINE=1` tests only
