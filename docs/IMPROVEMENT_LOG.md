# Improvement log

## 2026-09-14 — Cycle 1

PR: (this branch; URL after open)

### Why

The SCF agent pinned SCF **2026.2** as the source of truth.
Live HackIDLE and club APIs max at 2026.1.1 / 2026.1. Those APIs are not the pin.
`/workspace/scf-catalog` was not mounted on this VM.
Beacon now vendors 2026.2 slices from the official workbook (SHA-256 `9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835`).
Collect and seal write `scf_binding` on hashed evidence.
The witness chain still fails closed.

Catalog counts from the parse (match the pin): 1534 controls, 34 families, 316 ERLs, 249 mapped crosswalk frameworks.

### Next 3 items

1. Finish open PR #4: bind Conftest to the evidence bucket policy and reject IAM action wildcards (Greptile P1).
2. Close the lake gap: S3 access logging and CloudTrail data events for the evidence bucket; seal those logs as lake evidence.
3. CRA Article 14 early-warning packer (product ID, awareness time, CVE / exploitation signal, collector source).

### Blockers

- `/workspace/scf-catalog/raw/api/` is not in this environment. Re-parse if that catalog tree is later mounted.
- Live HackIDLE / GRCEngClub APIs remain 2026.1.x. Do not treat them as 2026.2.
- The offline bundle is a slice (IAC-01, CRY-05, QTS-*, E-QTS-*). It is not the full 1534-control workbook.
- Repo stays private. No production AWS apply in this cycle.
