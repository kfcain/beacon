---
name: beacon-local-mock
description: Install the Python Beacon engine, pin SCF offline, and seal fixture evidence with beacon init, seed, collect, and check.
---

# Local mock loop

Use this skill to install the Python engine and seal fixture evidence. No cloud key is required.

## Steps

1. Use Python 3.11 or later.
2. Install the locked environment from the repo root.
3. Create the workspace.
4. Seal builtin fixtures.
5. Check the chain.
6. Collect one offline control target when you need a named control.

## Commands

```bash
uv sync --frozen --extra dev
uv run --frozen beacon init
uv run --frozen beacon seed
uv run --frozen beacon check
BEACON_SCF_OFFLINE=1 uv run --frozen beacon collect --target IAC-02
BEACON_SCF_OFFLINE=1 uv run --frozen beacon collect --target CRY-07
BEACON_SCF_OFFLINE=1 uv run --frozen beacon collect --plugin scf.catalog.offline --fixture
```

`pip install -e '.[dev]'` is the same install when `uv` is absent. Run `beacon` from that virtualenv.

`beacon init` creates `.beacon/`, the recorder key, the witness key, and a local RFC 3161 TSA. `beacon seed` seals builtin fixtures. `beacon check` fails closed with `E_NO_CHECKPOINT` when a record has no checkpoint.

Offline `--target` values in this pin are IAC-02 and CRY-07. The catalog plugin target is GOV-02. Use `--plugin scf.catalog.offline` for that pack. Leave `--target` off that plugin command.

Without cloud credentials, collectors seal fixtures. A live CLI failure is sealed as `live_failed`. It stays a failure.

## Success

- `beacon check` exits 0 after `beacon seed`.
- `.beacon/chain/records.jsonl` and `.beacon/chain/checkpoints.jsonl` exist.
- Private keys stay in `.beacon/keys/`.

## Stop

Stop when a command would print a cloud key, a token, or a `.pem` body. Keep those values in the local secret store.

Stop when you need live cloud bytes. Switch to an approved scope and `beacon-scope`. A fixture seal is not live evidence.

Stop when `beacon check` exits non-zero. An unchecked chain is not verified evidence.
