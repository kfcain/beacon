---
name: beacon-overview
description: Say what Beacon is, which surface to use, and which later skill runs the job.
---

# Beacon overview

Use this skill first. It picks the surface and the next skill.

Beacon is a custody-first local evidence engine. You run it on your machine. An optional AWS lake stores sealed copies after the local seal. Beacon is not a SaaS GRC product. It does not file an audit opinion, a QSA assessment, or a FedRAMP 3PAO package.

This repo has two surfaces:

- The Python engine is the `beacon` CLI, the TUI, and `beacon serve`. Data lives in `.beacon/`. Read `docs/HOW_IT_WORKS.md`.
- The assurance workspace is `assurance/`. It is a Node GUI, API, CLI, and MCP server. Read `assurance/README.md`. It does not load the Python plugins or the Python private keys.

A seal records collected bytes on a witness chain. A seal does not mean a control is met.

## Next skill

| Job | Skill |
| --- | --- |
| Install, fixture collect, and check | `beacon-local-mock` |
| Scope init, import, and hash | `beacon-scope` |
| Claim words and receipts | `beacon-custody-claims` |
| SCF 2026.3 pin and legacy ids | `beacon-scf-pin` |
| Terraform gate before merge | `beacon-perch-gate` |
| TUI or GUI | `beacon-ui` |
| GitHub workflows and local tests | `beacon-ci` |

The index is `skills/README.md`.

## Success

You can name the surface, the command, and the status word before you edit.

## Stop

Stop when the task asks for a compliance claim, a FedRAMP submission, or a public trust-center host. Those results are outside this repo. Read `LIMITS.md`.

Stop when the task mixes the Python `.beacon/` keys with the assurance workspace. Keep the two runtimes apart.
