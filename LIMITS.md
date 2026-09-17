# LIMITS

Beacon is an evidence engine. It is not a substitute for an audit opinion, a QSA assessment, or a FedRAMP 3PAO package.

## Honest coverage

- Builtin collectors are `aws.inspector`, `azure.inspector`, and `gcp.inspector`. They are thin CLI wrappers (`aws` / `az` / `gcloud`) plus sealed fixtures. They are not a full copy of GRC Engineering Club inspector scripts or Paramify's fetcher catalog.
- The unified SCF engine maps a control id to overlapping fetchers. It does not evaluate maturity, compensating controls, or residual risk.
- Offline mode (`BEACON_SCF_OFFLINE=1`) ships control JSON for **IAC-01** and **CRY-05** only. That slice is not the 2026.2 catalog pin. It does not vendor the full SCF workbook or `controls.json`.
- Builtin plugin `scf.catalog.offline` verifies a slim SCF **2026.2** pin (`beacon/scf/catalog/`: `PIN.json`, `summary.json`, `families.json`, `index-meta.json`). The pin stores counts, family rows, 249 mapped crosswalk **framework ids**, and workbook SHA-256 `9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835`. Air-gap collect uses those JSON files only. The official `.xlsx` workbook is not vendored and is not required. If that workbook file is present next to the pin, the collector hashes it and fails closed on mismatch. The collector does not load `controls.json` or licensed control prose. Live HackIDLE / GRCEngClub APIs are not authoritative for 2026.2. Set `BEACON_SCF_CATALOG_PATH` to point at another pin directory. The collector fails closed on version, missing-file, SHA-256, count, or crosswalk-id mismatch.
- Live collection needs working cloud CLIs and credentials. Missing credentials use fixtures. A live API or CLI failure is sealed as `live_failed` and is never converted into a passing fixture.
- The local RFC 3161 TSA uses a workspace certificate created by `beacon init`. The token is CMS SignedData with `id-ct-TSTInfo`. The local signer signs TSTInfo with RSA-SHA256 (no signedAttrs). That timestamp proves ordering inside this workspace. It is not a publicly trusted timestamp authority unless you set `BEACON_TSA_URL` to one and supply a matching trust anchor.
- `beacon push` writes a local sealed pack (records, checkpoints, public keys) plus Markdown. When `BEACON_S3_BUCKET` is set, it also writes the pack to `exports/packs/` on the AWS evidence lake. It does not upload to Paramify or any other GRC SaaS.
- GUI and TUI drive the same collect/check/push functions. They do not add extra assurance.
- Beacon does not generate OSCAL, SSPs, or POA&M documents.
- The CRA Article 14 drop-in (`cra.art14.early_warning`) packs early-warning **signals**. A CISA KEV hit or a high severity score is not product exploitation and is not a notification decision. Beacon does not file ENISA or CSIRT reports, send external mail, or give legal advice.
- Remote S3/DynamoDB storage does not prove that evidence content is true. It stores sealed bytes, hashes (`sha256`, `input_sha256`, `audit_sha256`), and an index. Hash mismatch checks detect altered artifacts. They are not an audit opinion. A 24-hour freshness window does not prove the observation is true.

## Fail closed

`beacon check` returns `E_NO_CHECKPOINT` when any sealed record is not covered by a Merkle/TSA checkpoint. Do not treat an unchecked chain as verified evidence. AWS dual-write does not replace that check.
