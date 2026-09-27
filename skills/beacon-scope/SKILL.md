---
name: beacon-scope
description: Create, import, show, and hash a Beacon assessment scope, then bind that pair into collect and check.
---

# Assessment scope

Use this skill when evidence must carry `scope_id` and `scope_sha256`.

A scope file names the boundary, the frameworks, the data classes, the exclusions, and the allowed evidence kinds. The file is `.beacon/scopes/{scope_id}.json`.

## Steps

1. Start from `beacon init` when `.beacon/` is missing. See `beacon-local-mock`.
2. Create a starter scope or import a reviewed file.
3. Print the canonical hash.
4. Pass the same `--scope` to collect and check.
5. Read `docs/VERIFIED_WORKFLOW.md` and `examples/scopes/aws-ebs.example.json` before a live collector.

## Commands

```bash
beacon scope init --id prod-commercial
beacon scope show --id prod-commercial
beacon scope hash --id prod-commercial
beacon scope list
beacon scope import --file approved-scope.json
beacon collect --scope prod-commercial --target IAC-02
beacon check --scope prod-commercial
```

`BEACON_REQUIRE_SCOPE=1` makes a missing `--scope` fail closed. The default is off.

`beacon scope hash` prints `content_sha256()`. Copy that digest. Do not type a new one.

For the EBS example, copy `examples/scopes/aws-ebs.example.json`, review the account, the regions, and the volume inventory, then import that reviewed file.

```bash
beacon collect --plugin aws.ebs.encryption --scope aws-ebs-review --live
beacon evaluate --scope aws-ebs-review --control CRY-07
```

`--live` needs approved credentials outside the repo. The default evaluation makes no model call.

## Success

- `beacon scope show --id <id>` prints the document.
- `beacon scope hash --id <id>` prints 64 hex characters.
- A later `beacon check --scope <id>` exits 0 when the sealed payloads use that same hash.

## Stop

Stop when the scope file is missing or the hash does not match the sealed payload. `beacon check` fails closed on that mismatch.

Stop when the id is unsafe. `beacon scope init` rejects an unsafe id.

Stop when the task asks you to invent a framework id or an SCF control id inside the scope. Use ids from `beacon-scf-pin`.
