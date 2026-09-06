# Beacon Assurance Workspace

A working application for evidence, validation, framework records, documentation, sandbox trust-center delivery, and MCP. The same domain engine powers the hosted application and the portable GUI/API/CLI/MCP runtime.

## Start locally

Requires Node 24 or later for the portable SQLite runtime.

```sh
npm ci
npx vite build --config portable/vite.config.ts
```

Set `BEACON_TOKENS_JSON` through your local secret mechanism to a JSON array of records with `token` (at least 32 characters), `workspace`, `role` (`reader` or `operator`), and optional `actor`. Generate a unique random token; do not reuse a sample. Set `BEACON_DATABASE` to a protected path. Then:

```sh
node portable/server.mjs
```

Open `http://127.0.0.1:8787`, sign in with the assigned token, and explore the workspace. `/product` is the product homepage; `/trust` opens the sandbox trust center. The server binds loopback by default. For remote use, configure TLS and `BEACON_ORIGIN`; see `docs/PRODUCTION.md`.

## MCP

```sh
node portable/mcp.mjs
```

Use `portable/mcp-config.example.json`, replacing absolute paths. Point `BEACON_DATABASE` and `BEACON_WORKSPACE` at the same workspace as the portable API. Stdio is read-only unless `BEACON_MCP_WRITES=true`. Tools: `beacon_status`, `beacon_claim`, `beacon_validate`, `beacon_run_demo`, `beacon_document`, `beacon_verify`, `beacon_trust_release`. Streamable HTTP is available at `/api/mcp` with API authentication. The private hosted application's access gate does not provide external OAuth client onboarding.

## Try the full workflow

1. Open ENC-01; inspect scope, evidence and limitations.
2. Run healthy, drift, missing-Region, denied, stale and tampered scenarios.
3. Record a provider conclusion and update the implementation narrative.
4. Generate and download a versioned draft record.
5. Inspect selected framework mappings; search the full pinned CR26 rules/KSI catalog and save a requirement draft.
6. Create a sandbox trust release and synchronize its publication.
7. Execute an MCP tool in Integrations and inspect the actual JSON-RPC response.
8. Export the forensic evidence bundle and verify its hashes with the CLI.

## AWS collection and CI

`collectors/aws.py` is an actual read-only boto3 collector for EBS defaults, CloudTrail status and root MFA. It has been tested with controlled SDK responses, not deployed to a live account. Install `collectors/requirements.lock` with hash enforcement and supply an independently approved scope file. One account per job; CloudTrail needs explicit trail ARNs; IAM uses one account-level scope entry.

```sh
python -m pip install --require-hashes -r collectors/requirements.lock
python collectors/aws.py --scope approved-scope.json --claim ENC-01 --output observation.json
node portable/cli.mjs evaluate --evidence observation.json --scope approved-scope.json --claim ENC-01
```

A repeatable CI verification gate adds `--require-live --envelope signature.json --registry trusted-signers.json --job approved-job.json`. It rejects absent, untrusted, stale or mismatched provenance. See `collectors/kms_sign.py`, `portable/verify-signature.mjs` and `deploy/ci-gate.example.yml` for the separate signing path and required deployment policy.

One-time ingestion uses `portable/cli.mjs admit`, which verifies the signature and a passing observation before atomically consuming the approved job ID in a persistent private ledger. It rejects duplicate jobs, including concurrent submissions. Offline `evaluate` remains repeatable. See [Admission deployment and recovery](docs/ADMISSION.md) for exact commands, protected-policy requirements, receipt recovery and the database rollback limitation.

## Policy and procedure mapping

Documents now accepts JSON reports from [your GRC PDF Mapper](https://github.com/kfcain/grc-pdf-mapper), preserves document versions, shows source statements and proposed mappings, and records provider mapping decisions. Accepted relationships can link to Beacon claims and generated records. Direct PDF/DOCX/Markdown uploads use a separately configured private mapper API. See [Document mapping](docs/DOCUMENT-MAPPING.md) for setup, limits and the actual-engine integration test.

## Verification

```sh
node --test tests/beacon/*.test.mjs
python3 tests/beacon/test_collector.py
```

34 Node tests and 9 Rego tests passed after the infrastructure/TUI update, along with an actual Python mapper/API integration run. The 4 collector tests passed in the earlier milestone. Both the Worker and portable React client built successfully. Docker was unavailable, so images were not built/scanned. Browser visual QA was not performed. Hosted API persistence is provisioned at private deployment.

## Scope and source

All initial observations are explicitly simulated. Imported live-labeled observations remain unverified. Production publication is rejected. The application is not FedRAMP certified, an independently validated assessment, or a complete substitute for required package materials.

The CR26 reference contains 246 FRRs and 46 KSIs from official version 2026.07.14.01, commit 58efbf3d898496dd4a3a419eba78e458bbad5cb6. Selected cross-framework mappings are supporting candidates for review; the record editor does not claim official SDR schema conformance.

See [production milestone status](docs/PRODUCTION.md), [sales-engineer walkthrough](docs/SALES-ENGINEER-WALKTHROUGH.md), and `deploy/` for container/runtime/CI examples. This application is added alongside the legacy Python Beacon prototype. The new production path does not load its arbitrary plugins, private keys or custom TSA. Legacy security findings remain documented rather than silently certified as fixed.

Organization inventory, capstone review, local security boundaries, continuous validation, and GUI/TUI demonstrations: [Organization assurance blueprint](docs/ORG-ASSURANCE-BLUEPRINT.md). The infrastructure path supports five narrow configuration checks and explicitly unverified imports; live organization discovery and signed infrastructure admission remain outstanding.
