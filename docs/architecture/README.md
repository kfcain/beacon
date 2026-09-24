# Architecture notes

Read [How Beacon works](../HOW_IT_WORKS.md) before these notes. Each file records one decision. The custody path is not repeated here.

- [assessment-scope-and-jev.md](assessment-scope-and-jev.md) — assessment boundary, the `scope_id` / `scope_sha256` bind, and the judgment-receipt gate for claim words.
- [beacon-assurance-stack.md](beacon-assurance-stack.md) — workshop, tags, ledger, pack compilers, git policy, and trust center, with shipped phases and design phases labeled.
- [beacon-evidence-lake.md](beacon-evidence-lake.md) — local seal first, then optional AWS S3 and DynamoDB dual-write. Drawing: [beacon-evidence-lake.drawio](beacon-evidence-lake.drawio).
- [terraform-compliance.md](terraform-compliance.md) — maps each `deploy/aws` control to the lake requirement and the Rego check.
