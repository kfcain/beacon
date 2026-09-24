# beacon.scope

Schema stub for an assessment scope document and a Jev judgment receipt.

The models validate JSON and compute a canonical SHA-256. `decide_claim` returns whether Beacon code may attach a positive claim. The function does not emit the words compliant, evidenced, or proven.

This package does not collect evidence, seal the witness chain, push to the lake, or call Jev. The design is [docs/architecture/assessment-scope-and-jev.md](../../docs/architecture/assessment-scope-and-jev.md).

`scope_id` here is the assessment document id. It is not `BEACON_TENANT_ID` or `BEACON_WORKSPACE_ID`.
