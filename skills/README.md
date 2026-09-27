# Beacon agent skills

These skills teach an agent the Beacon loop. They are plain Markdown. Cursor, Claude Code, Codex, and other agents can read the same files.

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

Each skill file is `skills/<name>/SKILL.md`.

## Install

Cursor loads `.cursor/skills/<name>` in this repo. Those entries are links to `skills/<name>`.

Claude Code reads `.claude/skills/<name>/SKILL.md`. Codex reads `$CODEX_HOME/skills/<name>/SKILL.md` (often `~/.codex/skills`). Link each folder you need:

```bash
mkdir -p .claude/skills "$HOME/.codex/skills"
for name in beacon-overview beacon-local-mock beacon-scope beacon-custody-claims beacon-scf-pin beacon-perch-gate beacon-ui beacon-ci
do
  ln -s "$(pwd)/skills/$name" ".claude/skills/$name"
  ln -s "$(pwd)/skills/$name" "$HOME/.codex/skills/$name"
done
```

Another agent can open `skills/README.md` and then the one skill file. No secret belongs in these files.

`perch setup cursor` writes `.cursor/rules/perch.mdc`. That file is the upstream Perch helper. `beacon-perch-gate` is the Beacon gate.
