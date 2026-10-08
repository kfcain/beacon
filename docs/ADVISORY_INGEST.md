# Advisory ingest

`beacon advisory-ingest` reads a model-assisted check export from an ai-gate-ledger folder. The result is advisory evidence. A model verdict does not set a control result.

`claim_status` stays `unverified`. `control_satisfied` stays false. `assurance_claim` stays false. A verdict disposition is `needs_review` or `advisory_observed`.

## Command

```bash
beacon advisory-ingest \
  --file exports/beacon/2026-10-07.json \
  --ledger-root /path/to/ai-gate-ledger

beacon advisory-ingest \
  --file exports/beacon/2026-10-07.json \
  --ledger-root /path/to/ai-gate-ledger \
  --cicd exports/cicd/2026-10-07.jsonl \
  --dry-run
```

`--ledger-root` is the ledger folder on this machine. Receipt paths in the export are absolute paths under the export `ledger_root`. Beacon strips that prefix and reads the file under `--ledger-root`. Beacon does not follow a path that sits outside that prefix.

`--dry-run` prints the receipts and writes nothing.

## Checks

The command stops on the first failure and writes nothing.

1. The beacon file schema must be `ai-gate-ledger/beacon-advisory@2`. `advisory` must be true. `evidence_class` must be `advisory`. A `--cicd` file uses `ai-gate-ledger/cicd-receipt-row@2` on every row. Zero CI/CD rows is valid.
2. Beacon runs `python3 verify.py --json` in `--ledger-root`. The export field `ledger_verify` is ignored. A non-OK verify stops the ingest.
3. Beacon recomputes the sha256 of the export file, of each receipt file, and of the last line of each `ledger_heads` file. A mismatch stops the ingest.
4. One receipt is written per ledger run. `kind` is `model_advisory`. `flag: true` or a non-null `held` reason sets `disposition` to `needs_review`. Any other verdict sets `advisory_observed`. The export field `receipt_status` is stored as `ledger_integrity`. That field means the ledger file check. It is not a control status.
5. `scf_version`, `scf_id`, and `legacy_scf` are copied only when the export has them. Beacon does not infer an id. `scf_id` must exist in the pinned SCF 2026.3 objective rows. An unknown id is dropped and the reason is stored. A row with no SCF id is `unmapped`.
6. A CI/CD row is `ledger_integrity: verified` only when the CI receipt file is under the rebased ledger root and Beacon's sha256 matches the row. `derived` must contain NIST SP 800-53 ids only, for example `AC-6` or `AC-02(01)`.

The command does not emit the words MET, pass, satisfied, compliant, evidenced, or proven.

## Storage

Receipts are written under `.beacon/evidence/advisory/<export-date>/`. One witness record is appended with `seal_payload`. The record payload lists each receipt path and sha256. `create_checkpoint` covers that record. `beacon check` still fails closed when checkpoint coverage is missing.

The witness record is custody of the advisory files. `control_satisfied` and `assurance_claim` stay false.
