---
name: beacon-custody-claims
description: Keep Beacon claim words fail-closed. A seal, a ledger count, and a Perch receipt stay unverified until decide_claim permits a linked receipt.
---

# Custody and claims

Use this skill before you write a status word about evidence, a ledger, a pack, or a Perch gate.

## Words

A seal records bytes on the witness chain. Two Ed25519 keys sign each record. `beacon check` covers those records with a checkpoint.

The claim words are compliant, evidenced, and proven. Beacon may show one of those words only when `decide_claim` returns permitted and the same view shows the linked `receipt_id`. The receipt must match the scope hash, the evidence hash, and the receipt id. The default score minimum is 1.0.

Use the status word unverified for every other result.

## What stays unverified

- A green `beacon check` shows custody. It does not permit a claim word.
- `beacon ledger summary` counts evidence methods. Class C needs at least 2. Class D needs at least 4. A shortfall is a package gap. A shortfall of zero is still not a claim.
- `beacon pack compile` writes draft JSON. It is not a FedRAMP submission.
- `beacon trust publish` needs `BEACON_TRUST_CENTER_EXPORT=1`. It writes a local tree. It does not host a site.
- `beacon delivery` sets `assurance_claim` false.
- `beacon perch-receipt` writes `claim_status` `unverified` and `sealed` false. See `beacon-perch-gate`.
- Legacy `decide_claim` receipts cannot authorize claims. This repo has no live Jev client.

The code gate is `decide_claim` in `beacon/scope/document.py`. Read `docs/architecture/assessment-scope-and-jev.md` before you change it.

## Commands

```bash
beacon check --scope prod-commercial
beacon ledger summary --scope prod-commercial --class c
beacon receipts --scope prod-commercial
beacon perch-receipt --mock
```

## Success

The sentence you show names the command, the scope id when one exists, and the status word unverified. A claim word appears only beside a permitted `decide_claim` result and a visible `receipt_id`.

## Stop

Stop when a seal, a green test, a Perch exit 0, or a ledger shortfall of zero is the only evidence. Those results stay unverified.

Stop when the view has a receipt file and no linked `receipt_id`. A file alone is not a link.

Stop when you would edit `decide_claim` to return a claim word. The function returns permitted or a machine reason. The caller prints the word.
