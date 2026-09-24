# beacon.scope

Schema stub for an assessment scope document and a Jev judgment receipt.

The models validate JSON and compute a canonical SHA-256. `decide_claim` returns whether Beacon code may attach a positive claim. The function does not emit the words compliant, evidenced, or proven.

Phase 1 stores one file at `.beacon/scopes/{scope_id}.json`.

```bash
beacon scope init --id prod-commercial
beacon scope show --id prod-commercial
beacon scope hash --id prod-commercial
```

`init` writes schema version 1. The catalog pin label is `2026.3`. The framework id is the pillar id `general-nist-800-53-r5-2`. The boundary system is `workspace`. The file has no cloud account and no credential. A second `init` for the same id fails closed. `show` prints the document. `hash` prints `content_sha256()`. An unsafe id, a missing file, or a scope id that does not match the file fails closed.

`beacon collect --scope` loads that file and copies `scope_id` plus `content_sha256()` into each observation payload. `beacon check` recomputes the hash and fails closed on a missing file or a mismatch. A payload with no pair stays on the current check rules. `beacon push` copies the pair from the sealed payload into the pack manifest. It does not write a different scope. `BEACON_REQUIRE_SCOPE=1` requires `--scope` on collect and check. The witness `Record` stays version 1. This package does not call Jev.

```bash
beacon collect --scope prod-commercial --target IAC-02
beacon check --scope prod-commercial
```

The design is [docs/architecture/assessment-scope-and-jev.md](../../docs/architecture/assessment-scope-and-jev.md).

`draft_v2.py` is a schema version 2 workshop draft. It wraps a version 1 document. `beacon scope init` does not write it. See [docs/architecture/beacon-assurance-stack.md](../../docs/architecture/beacon-assurance-stack.md).

`scope_id` here is the assessment document id. It is not `BEACON_TENANT_ID` or `BEACON_WORKSPACE_ID`.
