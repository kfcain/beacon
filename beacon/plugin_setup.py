"""Install the Beacon skill pack for Cursor, Claude Code, Cowork, Codex, and pi.

The source of truth is the ``plugin/`` directory. This module links or copies
those files. It does not call Perch and it does not seal a receipt.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import click

from beacon.errors import E_PLUGIN_SETUP, BeaconError, fail

SKILL_NAMES: tuple[str, ...] = (
    "beacon-overview",
    "beacon-local-mock",
    "beacon-scope",
    "beacon-custody-claims",
    "beacon-scf-pin",
    "beacon-perch-gate",
    "beacon-ui",
    "beacon-ci",
)

PLATFORMS: tuple[str, ...] = (
    "cursor",
    "claude-code",
    "claude-cowork",
    "codex",
    "pi",
    "skills",
)

CLAUDE_COWORK_NOTE = (
    "This write uses the Claude Code skill path. "
    "A Cowork cloud session can read .claude/skills/ in the cloned repository. "
    "Claude Cowork on the desktop does not scan that folder. "
    "Upload each skill zip from Customize, or enable the skill on the claude.ai account. "
    "The zip root is the skill folder. The file name is SKILL.md."
)

_INDEX_NAME = "BEACON-SKILLS.md"
_GATE_NAME = "PERCH-GATE.md"
_SKIP_DIRS = {"__pycache__", ".pytest_cache"}


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    path: Path


@dataclass(frozen=True)
class PlatformDest:
    path: Path
    kind: str
    note: str


@dataclass(frozen=True)
class _Planned:
    action: dict[str, str]
    write: Callable[[], None] | None


def platform_dest(
    platform: str,
    *,
    root: Path,
    user: bool,
    home: Path,
    codex_home: Path | None = None,
) -> PlatformDest:
    """Return the directory this platform reads."""
    name = _platform_name(platform)
    if name == "skills":
        if user:
            fail(E_PLUGIN_SETUP, "the skills platform installs into the project. Do not pass --user.")
        return PlatformDest(root / "skills", "skills", "")
    if name == "cursor" and user:
        return PlatformDest(home / ".cursor" / "plugins" / "local" / "beacon", "bundle", "")
    if name == "cursor":
        return PlatformDest(root / ".cursor" / "skills", "skills", "")
    if name in {"claude-code", "claude-cowork"}:
        note = CLAUDE_COWORK_NOTE if name == "claude-cowork" else ""
        base = home / ".claude" / "skills" if user else root / ".claude" / "skills"
        return PlatformDest(base, "skills", note)
    if name == "codex":
        if user:
            return PlatformDest(_codex_base(home, codex_home) / "skills", "skills", "")
        return PlatformDest(root / ".codex" / "skills", "skills", "")
    if name == "pi":
        # Pi reads user skills from ~/.pi/agent/skills. Project skills stay in .pi/skills.
        base = home / ".pi" / "agent" / "skills" if user else root / ".pi" / "skills"
        return PlatformDest(base, "skills", "")
    fail(E_PLUGIN_SETUP, f"unknown platform {platform}")


def find_plugin_root(start: Path | None = None) -> Path:
    """Locate the Beacon plugin directory."""
    override = os.environ.get("BEACON_PLUGIN_DIR")
    if override:
        return _require_plugin(Path(override))
    packaged = Path(__file__).resolve().parents[1] / "plugin"
    packaged_manifest = packaged / ".cursor-plugin" / "plugin.json"
    if packaged_manifest.is_file() and _manifest_name(packaged_manifest) == "beacon":
        return packaged
    origins: list[Path] = []
    if start is not None:
        origins.append(start)
    origins.append(Path.cwd())
    seen: set[Path] = set()
    for origin in origins:
        current = origin.resolve()
        for candidate in (current, *current.parents):
            if candidate in seen:
                continue
            seen.add(candidate)
            plugin = candidate / "plugin"
            manifest = plugin / ".cursor-plugin" / "plugin.json"
            if manifest.is_file() and _manifest_name(manifest) == "beacon":
                return plugin
    fail(E_PLUGIN_SETUP, "Beacon plugin directory not found. Run this command from a Beacon checkout.")


def load_skills(plugin_root: Path) -> list[Skill]:
    """Load the eight skills. Fail when the pack differs."""
    skills_dir = plugin_root / "skills"
    if not skills_dir.is_dir():
        fail(E_PLUGIN_SETUP, "plugin skills directory is missing")
    found = {
        path.name
        for path in skills_dir.iterdir()
        if path.is_dir() and not path.name.startswith(".") and (path / "SKILL.md").is_file()
    }
    expected = set(SKILL_NAMES)
    if found != expected:
        missing = sorted(expected - found)
        extra = sorted(found - expected)
        fail(
            E_PLUGIN_SETUP,
            f"the skill pack must be the eight Beacon skills. missing={missing} extra={extra}",
        )
    skills: list[Skill] = []
    for name in SKILL_NAMES:
        path = skills_dir / name
        text = (path / "SKILL.md").read_text(encoding="utf-8")
        meta = _frontmatter(text, name)
        skill_name = meta.get("name", "")
        description = meta.get("description", "")
        if Path(name).name != name or name in {".", ".."}:
            fail(E_PLUGIN_SETUP, f"skill name is not a single folder name: {name}")
        if skill_name != name:
            fail(E_PLUGIN_SETUP, f"skill {name} frontmatter name must be {name}")
        if not description:
            fail(E_PLUGIN_SETUP, f"skill {name} frontmatter description is empty")
        skills.append(Skill(name=name, description=description, path=path))
    return skills


def render_index(skills: list[Skill]) -> str:
    """Build the index written next to an installed skill folder."""
    lines = [
        "# Beacon agent skills",
        "",
        "These folders are the Beacon skill pack. Open one SKILL.md for the job.",
        "",
        "| Skill | Job |",
        "| --- | --- |",
    ]
    for skill in skills:
        job = " ".join(skill.description.split())
        job = job.replace("|", "/")
        lines.append(f"| `{skill.name}` | {job} |")
    lines.extend(
        [
            "",
            "Start with `beacon-overview` when the job is unclear.",
            "",
            "The SCF pin in the Beacon repository is `beacon/scf/catalog/`. The pin version is 2026.3.",
            "The mock path is `beacon perch-receipt --mock`. That command does not call Perch.",
            "A mock receipt has `claim_status` unverified and `sealed` false.",
            "Use the status word unverified until `decide_claim` returns permitted and the same view shows the linked `receipt_id`.",
            "",
            "The gate note beside this file is `PERCH-GATE.md`.",
            "",
            "No secret belongs in these files.",
            "",
        ]
    )
    return "\n".join(lines)


def install(
    platform: str,
    *,
    root: Path | None = None,
    dest: Path | None = None,
    user: bool = False,
    copy: bool = False,
    link: bool = False,
    dry_run: bool = False,
    force: bool = False,
    zip_dir: Path | None = None,
    home: Path | None = None,
    codex_home: Path | None = None,
) -> dict[str, object]:
    """Link or copy the skill pack. Return a JSON-ready plan."""
    if copy and link:
        fail(E_PLUGIN_SETUP, "pass --copy or --link")
    if user and dest is not None:
        fail(E_PLUGIN_SETUP, "pass --dest or --user")
    name = _platform_name(platform)
    if zip_dir is not None and name != "claude-cowork":
        fail(E_PLUGIN_SETUP, "pass --zip-dir only with claude-cowork")
    project = (root or Path.cwd()).resolve()
    if not project.is_dir():
        fail(E_PLUGIN_SETUP, f"project root does not exist: {project}")
    plugin_root = find_plugin_root(project)
    skills = load_skills(plugin_root)
    gate = plugin_root / _GATE_NAME
    if not gate.is_file():
        fail(E_PLUGIN_SETUP, "plugin PERCH-GATE.md is missing")
    user_home = (home or Path.home()).resolve()
    chosen = platform_dest(name, root=project, user=user, home=user_home, codex_home=codex_home)
    target = dest.resolve() if dest is not None else chosen.path
    _reject_source_dest(target, plugin_root)
    if dest is None:
        codex_override = codex_home is not None or bool(os.environ.get("CODEX_HOME", "").strip())
        if user and name == "codex" and codex_override:
            anchor = _codex_base(user_home, codex_home)
        elif user:
            anchor = user_home
        else:
            anchor = project
        _require_inside(target, anchor)
    if zip_dir is not None and zip_dir.exists() and not zip_dir.is_dir():
        fail(E_PLUGIN_SETUP, f"zip directory is not a directory: {zip_dir}")
    _assert_no_symlinks(plugin_root)
    mode = _choose_mode("copy" if copy else "link" if link else None, target, plugin_root)
    plans: list[_Planned] = []
    if chosen.kind == "bundle":
        plans.extend(_plan_bundle(plugin_root, target, mode=mode, dry_run=dry_run, force=force))
    else:
        plans.extend(
            _plan_skills(
                skills,
                target,
                gate=gate,
                mode=mode,
                dry_run=dry_run,
                force=force,
            )
        )
    if zip_dir is not None:
        plans.extend(_plan_zips(skills, zip_dir, dry_run=dry_run, force=force))
    if not dry_run:
        for plan in plans:
            if plan.write is None:
                continue
            try:
                plan.write()
            except (OSError, shutil.Error, zipfile.BadZipFile) as exc:
                fail(E_PLUGIN_SETUP, f"install write failed: {exc}")
    return {
        "ok": True,
        "platform": name,
        "dry_run": dry_run,
        "mode": mode,
        "kind": chosen.kind,
        "dest": str(target),
        "plugin_root": str(plugin_root),
        "note": chosen.note,
        "actions": [plan.action for plan in plans],
    }


def run_install(
    platform: str,
    *,
    root: Path | None = None,
    dest: Path | None = None,
    user: bool = False,
    copy: bool = False,
    link: bool = False,
    dry_run: bool = False,
    force: bool = False,
    zip_dir: Path | None = None,
    home: Path | None = None,
    codex_home: Path | None = None,
) -> int:
    """Print the install result as JSON. Return a process code."""
    try:
        result = install(
            platform,
            root=root,
            dest=dest,
            user=user,
            copy=copy,
            link=link,
            dry_run=dry_run,
            force=force,
            zip_dir=zip_dir,
            home=home,
            codex_home=codex_home,
        )
    except BeaconError as exc:
        click.echo(f"{exc.code}: {exc.message}", err=True)
        return 2
    click.echo(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m beacon.plugin_setup``."""
    command = _make_command("plugin-setup")
    try:
        command.main(args=argv, prog_name="python -m beacon.plugin_setup", standalone_mode=False)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1
    except click.ClickException as exc:
        exc.show()
        return exc.exit_code
    return 0


def register_commands(group: click.Group) -> None:
    """Add ``beacon plugin install`` and ``beacon plugin-setup``."""
    plugin = click.Group(
        "plugin",
        help="Install Beacon agent skills. Collector plugins stay on `beacon plugins`.",
    )
    plugin.add_command(_make_command("install"))
    group.add_command(plugin)
    group.add_command(_make_command("plugin-setup"))


def _make_command(name: str) -> click.Command:
    @click.command(name)
    @click.argument("platform", type=click.Choice(PLATFORMS, case_sensitive=False))
    @click.option("--root", "root", type=click.Path(path_type=Path, file_okay=False), default=None, help="Project that receives the skills. The default is the current directory.")
    @click.option("--dest", "dest", type=click.Path(path_type=Path, file_okay=False), default=None, help="Skill directory. This replaces the platform default.")
    @click.option("--user", is_flag=True, help="Write under the user home for that platform. Pi uses ~/.pi/agent/skills.")
    @click.option("--copy", "copy", is_flag=True, help="Copy files.")
    @click.option("--link", "link", is_flag=True, help="Symlink to the plugin source. Fail when a symlink cannot be created.")
    @click.option("--dry-run", is_flag=True, help="Print the plan. Write nothing.")
    @click.option("--force", is_flag=True, help="Replace a destination that differs.")
    @click.option("--zip-dir", "zip_dir", type=click.Path(path_type=Path, file_okay=False), default=None, help="With claude-cowork, write one zip per skill.")
    def command(
        platform: str,
        root: Path | None,
        dest: Path | None,
        user: bool,
        copy: bool,
        link: bool,
        dry_run: bool,
        force: bool,
        zip_dir: Path | None,
    ) -> None:
        """Install the eight Beacon skills, the index, and the Perch Gate note."""
        code = run_install(
            platform=platform,
            root=root,
            dest=dest,
            user=user,
            copy=copy,
            link=link,
            dry_run=dry_run,
            force=force,
            zip_dir=zip_dir,
        )
        if code:
            raise SystemExit(code)

    return command


def _platform_name(platform: str) -> str:
    lowered = platform.strip().lower()
    if lowered not in PLATFORMS:
        fail(E_PLUGIN_SETUP, f"unknown platform {platform}")
    return lowered


def _require_plugin(path: Path) -> Path:
    root = path.expanduser().resolve()
    manifest = root / ".cursor-plugin" / "plugin.json"
    if not manifest.is_file() or _manifest_name(manifest) != "beacon":
        fail(E_PLUGIN_SETUP, f"BEACON_PLUGIN_DIR is not the Beacon plugin: {root}")
    return root


def _codex_base(home: Path, codex_home: Path | None) -> Path:
    if codex_home is not None and str(codex_home).strip():
        return codex_home
    raw = os.environ.get("CODEX_HOME", "").strip()
    if raw:
        return Path(raw)
    return home / ".codex"


def _manifest_name(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail(E_PLUGIN_SETUP, "plugin manifest is not valid JSON")
    if not isinstance(data, dict):
        fail(E_PLUGIN_SETUP, "plugin manifest is not a JSON object")
    name = data.get("name")
    if not isinstance(name, str):
        fail(E_PLUGIN_SETUP, "plugin manifest name is missing")
    return name


def _frontmatter(text: str, skill: str) -> dict[str, str]:
    normalized = text.replace("\r\n", "\n")
    if not normalized.startswith("---\n"):
        fail(E_PLUGIN_SETUP, f"skill {skill} has no frontmatter")
    end = normalized.find("\n---\n", 4)
    if end < 0:
        fail(E_PLUGIN_SETUP, f"skill {skill} frontmatter does not close")
    text = normalized
    meta: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            fail(E_PLUGIN_SETUP, f"skill {skill} frontmatter line has no key")
        key, value = line.split(":", 1)
        meta[key.strip()] = value.strip()
    return meta


def _choose_mode(explicit: str | None, dest: Path, plugin_root: Path) -> str:
    if explicit in {"copy", "link"}:
        return explicit
    if _dest_in_checkout(dest, plugin_root) and _can_create_symlink(dest):
        return "link"
    return "copy"


def _dest_in_checkout(dest: Path, plugin_root: Path) -> bool:
    repo = plugin_root.parent.resolve()
    try:
        dest.resolve().relative_to(repo)
    except ValueError:
        return False
    return True


def _can_create_symlink(dest: Path) -> bool:
    """Return true when this destination can hold a file symlink and a directory symlink.

    The probe directory is removed before this function returns. Explicit ``--link``
    does not call this function. A failed probe selects copy.
    """
    anchor = _symlink_probe_anchor(dest)
    try:
        with tempfile.TemporaryDirectory(prefix=".beacon-symlink-probe-", dir=anchor) as folder:
            root = Path(folder)
            source_dir = root / "source"
            source_dir.mkdir()
            dir_link = root / "dir-link"
            dir_link.symlink_to(os.path.relpath(source_dir, start=dir_link.parent), target_is_directory=True)
            source_file = root / "file.txt"
            source_file.write_bytes(b"x")
            file_link = root / "file-link"
            file_link.symlink_to(os.path.relpath(source_file, start=file_link.parent), target_is_directory=False)
            return (
                dir_link.is_symlink()
                and file_link.is_symlink()
                and dir_link.resolve() == source_dir.resolve()
                and file_link.resolve() == source_file.resolve()
            )
    except (OSError, NotImplementedError):
        return False


def _symlink_probe_anchor(dest: Path) -> Path:
    """Pick an existing directory on the destination filesystem."""
    resolved = dest.resolve()
    current = resolved if resolved.is_dir() else resolved.parent
    while not current.exists():
        if current.parent == current:
            break
        current = current.parent
    if not current.is_dir():
        current = current.parent
    return current


def _reject_source_dest(dest: Path, plugin_root: Path) -> None:
    resolved = dest.resolve()
    source = plugin_root.resolve()
    if resolved == source or _is_inside(resolved, source) or _is_inside(source, resolved):
        fail(E_PLUGIN_SETUP, "destination must be outside the plugin source")


def _require_inside(path: Path, root: Path) -> None:
    if not _is_inside(path.resolve(), root.resolve()) and path.resolve() != root.resolve():
        fail(E_PLUGIN_SETUP, f"destination is outside the install root: {path}")


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return path != root


def _assert_no_symlinks(root: Path) -> None:
    if root.is_symlink():
        fail(E_PLUGIN_SETUP, f"plugin source contains a symlink: {root}")
    for path in root.rglob("*"):
        if path.is_symlink():
            fail(E_PLUGIN_SETUP, f"plugin source contains a symlink: {path}")


def _plan_bundle(plugin_root: Path, dest: Path, *, mode: str, dry_run: bool, force: bool) -> list[_Planned]:
    action = _plan_action(
        dest,
        plugin_root,
        kind="bundle",
        mode=mode,
        same=_same_tree(dest, plugin_root, mode),
        force=force,
    )

    def write() -> None:
        _replace(dest, force=True)
        if mode == "link":
            _symlink(dest, plugin_root)
            return
        _copy_tree(plugin_root, dest)

    return [_Planned(action, None if dry_run or action["op"] == "unchanged" else write)]


def _plan_skills(
    skills: list[Skill],
    dest: Path,
    *,
    gate: Path,
    mode: str,
    dry_run: bool,
    force: bool,
) -> list[_Planned]:
    if (dest.is_symlink() or dest.exists()) and not dest.is_dir():
        fail(E_PLUGIN_SETUP, f"destination is not a directory: {dest}")
    plans = [
        _plan_tree(dest / skill.name, skill.path, kind="skill", mode=mode, dry_run=dry_run, force=force)
        for skill in skills
    ]
    plans.append(
        _plan_file(
            dest / _INDEX_NAME,
            render_index(skills).encode("utf-8"),
            source=None,
            kind="index",
            mode="copy",
            dry_run=dry_run,
            force=force,
        )
    )
    plans.append(
        _plan_file(
            dest / _GATE_NAME,
            gate.read_bytes(),
            source=gate,
            kind="gate",
            mode=mode,
            dry_run=dry_run,
            force=force,
        )
    )
    return plans


def _plan_tree(
    dest: Path,
    source: Path,
    *,
    kind: str,
    mode: str,
    dry_run: bool,
    force: bool,
) -> _Planned:
    action = _plan_action(dest, source, kind=kind, mode=mode, same=_same_tree(dest, source, mode), force=force)

    def write() -> None:
        _replace(dest, force=True)
        if mode == "link":
            _symlink(dest, source)
        else:
            _copy_tree(source, dest)

    return _Planned(action, None if dry_run or action["op"] == "unchanged" else write)


def _plan_file(
    dest: Path,
    content: bytes,
    *,
    source: Path | None,
    kind: str,
    mode: str,
    dry_run: bool,
    force: bool,
) -> _Planned:
    target = source if source is not None else dest
    action = _plan_action(
        dest,
        target,
        kind=kind,
        mode=mode,
        same=_same_file(dest, content, source, mode),
        force=force,
    )

    def write() -> None:
        _replace(dest, force=True)
        if mode == "link" and source is not None:
            _symlink(dest, source)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)

    return _Planned(action, None if dry_run or action["op"] == "unchanged" else write)


def _plan_action(
    dest: Path,
    source: Path,
    *,
    kind: str,
    mode: str,
    same: bool,
    force: bool,
) -> dict[str, str]:
    exists = dest.is_symlink() or dest.exists()
    if exists and same and not force:
        op = "unchanged"
    elif exists and not same and not force:
        fail(E_PLUGIN_SETUP, f"destination exists and differs: {dest}. Pass --force to replace it.")
    else:
        op = mode
    return {"op": op, "kind": kind, "path": str(dest), "target": str(source)}


def _plan_zips(skills: list[Skill], zip_dir: Path, *, dry_run: bool, force: bool) -> list[_Planned]:
    plans: list[_Planned] = []
    for skill in skills:
        archive = zip_dir / f"{skill.name}.zip"
        if archive.parent != zip_dir:
            fail(E_PLUGIN_SETUP, f"zip path escapes the zip directory: {archive}")
        payload = _zip_members(skill)
        if archive.is_symlink():
            present = True
            same = False
        elif archive.is_file():
            present = True
            same = _zip_same(archive, payload)
        elif archive.exists():
            fail(E_PLUGIN_SETUP, f"zip path is not a file: {archive}")
        else:
            present = False
            same = False
        if present and same and not force:
            op = "unchanged"
        elif present and not same and not force:
            fail(E_PLUGIN_SETUP, f"destination exists and differs: {archive}. Pass --force to replace it.")
        else:
            op = "zip"
        action = {"op": op, "kind": "zip", "path": str(archive), "target": f"{skill.name}/SKILL.md"}

        def write(archive: Path = archive, payload: list[tuple[str, Path]] = payload) -> None:
            archive.parent.mkdir(parents=True, exist_ok=True)
            if archive.is_symlink() or archive.is_file():
                archive.unlink()
            elif archive.exists():
                fail(E_PLUGIN_SETUP, f"zip path is not a file: {archive}")
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                for arcname, file_path in payload:
                    handle.write(file_path, arcname=arcname)

        plans.append(_Planned(action, None if dry_run or op == "unchanged" else write))
    return plans


def _zip_members(skill: Skill) -> list[tuple[str, Path]]:
    if skill.path.is_symlink():
        fail(E_PLUGIN_SETUP, f"skill folder is a symlink: {skill.path}")
    root = skill.path.resolve()
    members: list[tuple[str, Path]] = []
    for file_path in sorted(path for path in skill.path.rglob("*") if path.is_file() or path.is_symlink()):
        if file_path.is_symlink():
            fail(E_PLUGIN_SETUP, f"skill file is a symlink: {file_path}")
        resolved = file_path.resolve()
        if not _is_inside(resolved, root):
            fail(E_PLUGIN_SETUP, "skill file path is not inside the skill folder")
        rel = file_path.relative_to(skill.path)
        if rel.is_absolute() or ".." in rel.parts or any("\\" in part or part in {"", ".", ".."} for part in rel.parts):
            fail(E_PLUGIN_SETUP, "skill file path is not inside the skill folder")
        arcname = f"{skill.name}/{rel.as_posix()}"
        if "\\" in arcname or arcname.startswith("/") or ".." in Path(arcname).parts:
            fail(E_PLUGIN_SETUP, "zip entry escapes the skill folder")
        members.append((arcname, file_path))
    if not members:
        fail(E_PLUGIN_SETUP, f"skill {skill.name} has no files")
    return members


def _zip_same(path: Path, payload: list[tuple[str, Path]]) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with zipfile.ZipFile(path) as handle:
            if sorted(handle.namelist()) != sorted(item[0] for item in payload):
                return False
            return all(handle.read(arcname) == file_path.read_bytes() for arcname, file_path in payload)
    except (zipfile.BadZipFile, OSError):
        return False


def _same_tree(dest: Path, source: Path, mode: str) -> bool:
    if not dest.is_symlink() and not dest.exists():
        return False
    if dest.is_symlink():
        if mode != "link":
            return False
        try:
            return dest.resolve(strict=True) == source.resolve(strict=True)
        except OSError:
            return False
    if mode == "link" or not dest.is_dir() or _contains_symlink(dest):
        return False
    return _tree_files(dest) == _tree_files(source)


def _same_file(dest: Path, content: bytes, source: Path | None, mode: str) -> bool:
    if not dest.is_symlink() and not dest.exists():
        return False
    if dest.is_symlink() or mode == "link":
        if mode != "link" or source is None or not dest.is_symlink():
            return False
        try:
            return dest.resolve(strict=True) == source.resolve(strict=True)
        except OSError:
            return False
    if not dest.is_file():
        return False
    return dest.read_bytes() == content


def _contains_symlink(root: Path) -> bool:
    return any(path.is_symlink() for path in root.rglob("*"))


def _tree_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    if root.is_file():
        return {root.name: root.read_bytes()}
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if _SKIP_DIRS.intersection(path.parts):
            continue
        files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def _replace(path: Path, *, force: bool) -> None:
    if not force or not (path.is_symlink() or path.exists()):
        return
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    shutil.rmtree(path)


def _symlink(link: Path, source: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    relative = os.path.relpath(source.resolve(), start=link.parent.resolve())
    link.symlink_to(relative, target_is_directory=source.is_dir())


def _copy_tree(source: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=False)
    for file_path in source.rglob("*"):
        if _SKIP_DIRS.intersection(file_path.parts):
            continue
        if file_path.is_symlink():
            fail(E_PLUGIN_SETUP, f"plugin source contains a symlink: {file_path}")
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(source)
        if rel.is_absolute() or ".." in rel.parts:
            fail(E_PLUGIN_SETUP, "skill file path is not inside the skill folder")
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file_path, out)


if __name__ == "__main__":
    raise SystemExit(main())
