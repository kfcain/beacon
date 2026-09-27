---
name: beacon-ci
description: Run the Beacon test workflows that already exist, and keep the Perch gate opt-in so required checks stay intact.
---

# Beacon CI

Use this skill before you add a workflow or you claim a check passed.

## Workflows in this repo

| File | Role |
| --- | --- |
| `.github/workflows/ci.yml` | Required Python checks. Matrix 3.11, 3.12, 3.13. Job name `Required checks`. |
| `.github/workflows/beacon-assurance.yml` | Node assurance workspace tests from the repo root. |
| `assurance/.github/workflows/verify.yml` | Same Node checks when that folder is the root. |
| `.github/workflows/perch-gate.yml` | Opt-in Perch scan. Not a required check. |

`ci.yml` sets `BEACON_SCF_OFFLINE=1` and `BEACON_FORCE_FIXTURE=1`. It installs with `uv sync --frozen --all-extras`. It runs `uv run --frozen pytest -ra`.

The Perch workflow runs on `workflow_dispatch`. A pull request runs the job only when the repository variable `PERCH_GATE_ON` is `true` and the path filter matches. The secret name is `PERCH_API_KEY`. An empty secret fails the job and sends no request. See `beacon-perch-gate`.

## Local commands

```bash
uv sync --frozen --all-extras
uv run --frozen pytest -q
make policy
```

`make policy` runs the Terraform Conftest checks under `policy/terraform`.

For the assurance workspace:

```bash
cd assurance
npm ci
npm test
```

## Success

The command you cite is one of the commands above, and you have its exit code from this workspace. A skipped Perch job is not a Perch pass.

## Stop

Stop when you would add the Perch job to `ci.yml` or to the required-check job. That change can fail every pull request that has no `PERCH_API_KEY`.

Stop when you would commit a key, a token, or a `.pem` file to make CI green.

Stop when you would say the live Perch API ran. Say that only after a human run with `PERCH_API_KEY` set outside the repo, and after the receipt has `live_api` true. That receipt stays `unverified`.
