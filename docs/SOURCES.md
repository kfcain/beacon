# Sources

Beacon uses public GRC engineering work as **shape references**. This repository does not vendor those codebases.

## GRC Engineering Club inspectors

- Org: [GRCEngClub](https://github.com/GRCEngClub)
- Toolkit: [GRCEngClub/claude-grc-engineering](https://github.com/GRCEngClub/claude-grc-engineering)
- Connectors used as the inspector shape: `plugins/connectors/aws-inspector`, `azure-inspector`, `gcp-inspector`
- Collect contract: CLI-backed probes (`aws` / `az` / `gcloud`), SCF-tagged findings (IAC-02, CRY-07, and related checks), fixture-friendly first run

Beacon's `CloudInspectorPlugin` follows that connector outline (probe identity, collect a small IAM + encryption surface, emit SCF-tagged findings). It does not copy the Node collect scripts.

## Paramify fetchers

- Upstream: [paramify/paramify-fetchers](https://github.com/paramify/paramify-fetchers)
- Fork reference: [kfcain/paramify-fetchers](https://github.com/kfcain/paramify-fetchers)
- Shapes used: `Fetcher` / category `PlatformSpec`, `collect()` runner, evidence envelope, and the TUI workspace (catalog / run / evidence / upload)

Beacon's `FetcherSpec`, drop-in `PLUGIN` loader, TUI tabs (Dashboard, Freshness, Validation, Push, System, Collect), and GUI pages follow that operator flow. Fetcher catalogs are not vendored.

## CISA KEV (signal shape)

- Feed: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Beacon uses the catalog **shape** (`cveID`, `vendorProject`, `product`, `dateAdded`) as an optional CRA Article 14 signal. The repo vendors a three-row synthetic slice only (`CVE-2099-*`). It does not vendor a live CISA dump. KEV listing is not treated as product exploitation. See [CRA_ART14.md](CRA_ART14.md).

## SCF hub

- API: [https://hackidle.github.io/scf-api/](https://hackidle.github.io/scf-api/)
- Project: [hackIDLE/scf-api](https://github.com/hackIDLE/scf-api)
- Live host version: SCF 2026.1.1 (CC BY-ND). **Not** the 2026.3 pin.
- Offline control bundle: `IAC-02` and `CRY-07` control JSON plus `beacon/scf/offline/summary.json`, for `BEACON_SCF_OFFLINE=1` tests only. That summary is a seed index aligned to the 2026.3 pin. It is not a live HackIDLE summary and it is not the catalog pin. Those ids are the 2026.3 Legacy SCF # maps of prior IAC-01 (IAM) and CRY-05 (data at rest).
- Offline catalog pin: `beacon/scf/catalog/` (SCF **2026.3** summary, families, 270 crosswalk framework ids, index-meta, workbook SHA-256 `5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697`). Collector: `scf.catalog.offline`. Air-gap collect does not need the `.xlsx` file. See [SCF_CATALOG.md](SCF_CATALOG.md).
