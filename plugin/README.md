# Beacon agent skills

This folder is the Beacon skill plugin. The files under `skills/` are the only copy of the skill text. `skills/` at the repository root and `.cursor/skills/` are links to this folder.

Pick one skill for the job. Start with `beacon-overview` when the job is unclear.

| Skill | Job |
| --- | --- |
| `beacon-overview` | What Beacon is, which surface to use, and which skill is next |
| `beacon-local-mock` | Install the Python engine, offline SCF, fixture collect, and `beacon check` |
| `beacon-scope` | Scope init, import, hash, and bind |
| `beacon-custody-claims` | Fail-closed status words and `decide_claim` |
| `beacon-scf-pin` | SCF 2026.3 pin, legacy ids, and hops |
| `beacon-perch-gate` | Preventive Terraform gate and the unverified receipt |
| `beacon-ui` | Python TUI and `beacon serve`, or the assurance workspace server |
| `beacon-ci` | Local tests and the GitHub workflows |

Each skill file is `skills/<name>/SKILL.md`. The gate note is [PERCH-GATE.md](PERCH-GATE.md).

## Pin and mock path

The SCF pin in the Beacon repository is `beacon/scf/catalog/`. `PIN.json` says version `2026.3`. Set `BEACON_SCF_OFFLINE=1` for the offline path. Read `beacon-scf-pin` before you cite a control id.

The mock gate command does not call Perch:

```bash
beacon perch-receipt --mock
```

A mock receipt has `claim_status` `unverified` and `sealed` false. Use the status word unverified until `decide_claim` returns permitted and the same view shows the linked `receipt_id`.

No secret belongs in this pack. The CI secret name is `PERCH_API_KEY`. Keep that key in the Actions secret store.

## Install

Run the commands from a Beacon checkout. The command reads this folder. `--root` is the project that receives the skills. The default root is the current directory.

`--dry-run` prints the plan and writes nothing. The command copies files when the destination is outside this repository. It links files when the destination is inside this repository. `--copy` and `--link` select one mode. `--force` replaces a destination whose bytes differ.

```bash
uv run beacon plugin install cursor --dry-run
uv run beacon plugin install cursor
uv run beacon plugin install claude-code
uv run beacon plugin install claude-cowork
uv run beacon plugin install codex
uv run beacon plugin install pi
uv run beacon plugin install skills
```

The same install is available as:

```bash
uv run beacon plugin-setup claude-code --dry-run
python -m beacon.plugin_setup codex --dry-run
```

| Platform | Project path | User path |
| --- | --- | --- |
| `cursor` | `.cursor/skills/<name>/` | `~/.cursor/plugins/local/beacon/` (the whole plugin) |
| `claude-code` | `.claude/skills/<name>/` | `~/.claude/skills/<name>/` |
| `claude-cowork` | `.claude/skills/<name>/` | `~/.claude/skills/<name>/` |
| `codex` | `.codex/skills/<name>/` | `$CODEX_HOME/skills/<name>/` or `~/.codex/skills/<name>/` |
| `pi` | `.pi/skills/<name>/` | `~/.pi/skills/<name>/` |
| `skills` | `skills/<name>/` | none |

Add `--user` to write the user path. `skills` has no user path. Add `--root <project>` to write into another project. Add `--dest <dir>` to override the skill directory.

```bash
uv run beacon plugin install claude-code --root ../other-repo
uv run beacon plugin install codex --user
uv run beacon plugin install cursor --user --link
```

Cursor can also load this directory as a plugin. The manifest is `.cursor-plugin/plugin.json`. The repository marketplace entry is `.cursor-plugin/marketplace.json` and its source is `plugin`. A local Cursor install of the whole folder is `~/.cursor/plugins/local/beacon`.

Claude Code can load this directory as a plugin. The manifest is `.claude-plugin/plugin.json`. The skill folders are the same `skills/` tree.

## Claude Cowork

`claude-cowork` writes the same files as `claude-code`.

A Cowork cloud session can read `.claude/skills/` when that folder is in the cloned repository. Claude Cowork on the desktop does not scan that folder. Enable the skill on the claude.ai account, or upload a zip from Customize. The zip root is the skill folder. The file name is `SKILL.md`.

```bash
uv run beacon plugin install claude-cowork --zip-dir dist/cowork-skills
```

That command writes one zip per skill. It also writes the project skill folders.

## Other assistants

Use `skills` to copy or link the pack into a `skills/` directory. Point the assistant at `skills/<name>/SKILL.md`. The index text the installer writes beside those folders is `BEACON-SKILLS.md`. The gate note it writes is `PERCH-GATE.md`.
