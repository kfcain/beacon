# LIMITS

Beacon is an evidence engine. It is not a substitute for an audit opinion, a QSA assessment, or a FedRAMP 3PAO package.

## Honest coverage

- Builtin collectors are `aws.inspector`, `azure.inspector`, `gcp.inspector`, and `aws.lake.logs`. The cloud inspectors are thin CLI wrappers (`aws` / `az` / `gcloud`) plus sealed fixtures. They are not a full copy of GRC Engineering Club inspector scripts or Paramify's fetcher catalog.
- `aws.lake.logs` reads S3 server access logs and CloudTrail data events from `BEACON_LOGS_BUCKET`. It seals a bounded extract and the object SHA-256. It does not copy raw AWS log objects into the evidence bucket. The only seal target is **IAC-01**. A different target is not sealed as IAC-01. The finding does not assert that IAC-01, FedRAMP, NIST 800-53, CMMC, or SOC 2 is met. CloudTrail rows must be `eventCategory` Data or `managementEvent` false. Gzip output is capped. No logs bucket uses the fixture. A live read failure stays `live_failed`.
- The unified SCF engine maps a control id to overlapping fetchers. It does not evaluate maturity, compensating controls, or residual risk.
- Offline mode (`BEACON_SCF_OFFLINE=1`) ships **IAC-01** and **CRY-05** only. It does not vendor the 1468-control SCF workbook.
- Live collection needs working cloud CLIs and credentials. Missing credentials use fixtures. A live API or CLI failure is sealed as `live_failed` and is never converted into a passing fixture.
- The local RFC 3161 TSA uses a workspace certificate created by `beacon init`. The token is CMS SignedData with `id-ct-TSTInfo`. The local signer signs TSTInfo with RSA-SHA256 (no signedAttrs). That timestamp proves ordering inside this workspace. It is not a publicly trusted timestamp authority unless you set `BEACON_TSA_URL` to one and supply a matching trust anchor.
- `beacon push` writes a local sealed pack (records, checkpoints, public keys) plus Markdown. When `BEACON_S3_BUCKET` is set, it also writes the pack to `exports/packs/` on the AWS evidence lake. It does not upload to Paramify or any other GRC SaaS.
- GUI and TUI drive the same collect/check/push functions. They do not add extra assurance.
- Beacon does not generate OSCAL, SSPs, or POA&M documents.
- Remote S3/DynamoDB storage does not prove that evidence content is true. It stores sealed bytes, hashes (`sha256`, `input_sha256`, `audit_sha256`), and an index. Hash mismatch checks detect altered artifacts. They are not an audit opinion. A 24-hour freshness window does not prove the observation is true.

## Fail closed

`beacon check` returns `E_NO_CHECKPOINT` when any sealed record is not covered by a Merkle/TSA checkpoint. Do not treat an unchecked chain as verified evidence. AWS dual-write does not replace that check.
