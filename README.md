# Beacon Assurance Workspace

The new interactive application is in [`assurance/`](assurance/README.md). It includes a portable GUI/API/MCP server, evidence validation, CR26 records, draft documentation and sandbox trust-center delivery.

[Run the new workspace](assurance/README.md) · [Production milestone status](assurance/docs/PRODUCTION.md) · [Sales-engineer walkthrough](assurance/docs/SALES-ENGINEER-WALKTHROUGH.md)

The earlier Python engine below remains a legacy prototype. Its local witness/TSA and plugin model are not production assurance. The new runtime does not load those plugins or private keys. Review the production milestone table before deployment.

---

# Beacon

Beacon is a GRC evidence engine. It collects cloud inspector evidence, maps it to Secure Controls Framework (SCF) 2026.1.1, and seals every result on a signed witness chain.

Package name: `beacon`. CLI name: `beacon`. Environment prefix: `BEACON_`. Data directory: `.beacon/`. MCP tools: `beacon_*`.

## Run

Python 3.10 or later is required.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
beacon init
beacon seed
beacon check
beacon serve
beacon tui
```

`beacon serve` starts the GUI (Dashboard, Freshness, Validation, Push, System).

`beacon tui` starts the Paramify-style terminal UI. The TUI adds a Collect screen.

## Collect

Without cloud credentials, inspectors seal **fixtures** through the witness chain. Live collection uses `aws`, `az`, and `gcloud`. A live failure is sealed as `live_failed`. It is never rewritten as a success fixture.

```bash
beacon collect --target IAC-01
beacon collect --target CRY-05
beacon collect --plugin aws.inspector
```

`--target IAC-01` and `--target CRY-05` select every loaded fetcher whose `FetcherSpec.scf_targets` overlap that control, then seal the results.

## Witness chain

- Recorder key and witness key are distinct Ed25519 keys.
- Each record carries both signatures and a previous-hash link.
- Checkpoints are SHA-256 Merkle roots timestamped with RFC 3161 (local TSA by default).
- `beacon check` **fails closed** with `E_NO_CHECKPOINT` when records are not covered by a checkpoint.

## SCF hub

Default API: `https://hackidle.github.io/scf-api/` (SCF 2026.1.1).

- Override base URL: `BEACON_SCF_API_BASE`
- Offline tests and air-gap: `BEACON_SCF_OFFLINE=1`

```bash
BEACON_SCF_OFFLINE=1 pytest
```

## Drop-in platforms

See [docs/PLUGINS.md](docs/PLUGINS.md). Example: [examples/echo_platform.py](examples/echo_platform.py).

```bash
export BEACON_PLUGIN_PATH=./examples/echo_platform.py
beacon plugins
beacon collect --plugin echo
```

## MCP

```bash
beacon mcp
```

Tools: `beacon_status`, `beacon_init`, `beacon_seed`, `beacon_check`, `beacon_collect`, `beacon_plugins`, `beacon_freshness`, `beacon_scf_lookup`, `beacon_push`, `beacon_validation`.

## Limits and sources

- [LIMITS.md](LIMITS.md) — what Beacon does not claim
- [docs/SOURCES.md](docs/SOURCES.md) — GRCEngClub inspectors and Paramify fetchers as shape references
