# Perch Gate

Perch Gate stops a Terraform miss before merge. Beacon keeps custody. A gate run is not a seal. A seal is not a statement that a control is met.

Use the skill `beacon-perch-gate` to install Perch, author a rule, wire CI, or write a receipt.

## Receipt

v0 writes a receipt and does not seal it. `claim_status` is `unverified`. `sealed` is false.

Use the status word unverified. The words compliant, evidenced, and proven need `decide_claim` permitted and a linked `receipt_id` in the same view. A green scan stays unverified.

The mock command does not call Perch:

```bash
beacon perch-receipt --mock
```

## Rules in this pack

These ids are rows in the vendored SCF 2026.3 objective sheet. Copy a framework hop only from `beacon/scf/offline/<scf_id>.json`. CRY-07 has offline JSON in this pin. The other three rules do not.

| Rule | SCF id | AO id | Legacy id on the row |
| --- | --- | --- | --- |
| `tf-encryption-at-rest` | CRY-07 | CRY-07_A02 | CRY-05 |
| `tf-no-public-acl` | IAC-25 | IAC-25_A06 | IAC-20 |
| `tf-required-logging` | MON-04 | MON-04_A02 | MON-01.4 |
| `tf-no-plaintext-secrets` | CFG-17.2 | CFG-17.2_A04 | CFG-09.2 |

The CI secret name is `PERCH_API_KEY`. Keep the key in the Actions secret store. Do not put the key in this pack.

The charter in the Beacon repository is `docs/architecture/perch-gate.md`.
