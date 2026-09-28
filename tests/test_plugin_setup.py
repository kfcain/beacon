"""Installer tests for the Beacon skill plugin."""

from __future__ import annotations

import json
import os
import re
import shutil
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.cli import main
from beacon.errors import E_PLUGIN_SETUP, BeaconError
from beacon.plugin_setup import (
    PLATFORMS,
    SKILL_NAMES,
    find_plugin_root,
    install,
    load_skills,
    main as plugin_main,
    platform_dest,
    render_index,
)

_REPO = Path(__file__).resolve().parents[1]
_SCF_IDS = {
    "CRY-07",
    "CRY-07_A02",
    "CRY-05",
    "IAC-25",
    "IAC-25_A06",
    "IAC-20",
    "MON-04",
    "MON-04_A02",
    "MON-01.4",
    "CFG-17.2",
    "CFG-17.2_A04",
    "CFG-09.2",
}
_ID_RE = re.compile(r"[A-Z]{2,5}-\d+(?:\.\d+)?(?:_A\d+)?")


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BEACON_PLUGIN_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)


def test_pack_is_eight_linked_skills() -> None:
    assert len(SKILL_NAMES) == 8
    assert len(PLATFORMS) == 6
    plugin = _REPO / "plugin"
    for name in SKILL_NAMES:
        source = plugin / "skills" / name / "SKILL.md"
        assert source.is_file()
        text = source.read_text(encoding="utf-8")
        assert text.startswith("---\n")
        assert f"name: {name}\n" in text
        assert (_REPO / "skills" / name / "SKILL.md").resolve() == source.resolve()
        assert (_REPO / ".cursor" / "skills" / name / "SKILL.md").resolve() == source.resolve()
    loaded = load_skills(plugin)
    assert [skill.name for skill in loaded] == list(SKILL_NAMES)


def test_manifests_stay_inside_the_plugin() -> None:
    plugin = _REPO / "plugin"
    for rel in ("plugin.json", ".cursor-plugin/plugin.json", ".claude-plugin/plugin.json"):
        data = json.loads((plugin / rel).read_text(encoding="utf-8"))
        assert data["name"] == "beacon"
        assert data["version"] == "0.1.0"
    cursor = json.loads((plugin / ".cursor-plugin" / "plugin.json").read_text(encoding="utf-8"))
    skills = Path(cursor["skills"])
    assert not skills.is_absolute()
    assert ".." not in skills.parts
    assert (plugin / skills).is_dir()
    market = json.loads((_REPO / ".cursor-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert market["plugins"][0]["source"] == "plugin"
    assert market["plugins"][0]["name"] == "beacon"


def test_gate_note_uses_pinned_ids_only() -> None:
    text = (_REPO / "plugin" / "PERCH-GATE.md").read_text(encoding="utf-8")
    found = set(_ID_RE.findall(text))
    assert found <= _SCF_IDS
    assert {"CRY-07", "CRY-07_A02", "IAC-25", "MON-04", "CFG-17.2"} <= found
    assert "unverified" in text
    assert "sealed" in text
    assert "PERCH_API_KEY=" not in text
    readme = (_REPO / "plugin" / "README.md").read_text(encoding="utf-8")
    assert "beacon/scf/catalog/" in readme
    assert "2026.3" in readme
    assert "beacon perch-receipt --mock" in readme
    assert "claude-cowork" in readme
    assert "PERCH_API_KEY=" not in readme
    assert "AKIA" not in readme
    assert "BEGIN PRIVATE" not in readme
    assert "~/.pi/agent/skills/<name>/" in readme
    assert "~/.pi/skills" not in readme
    assert "--link` always links" in readme


def test_platform_paths(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    home = tmp_path / "home"
    codex = tmp_path / "codex"
    expected = {
        ("cursor", False): root / ".cursor" / "skills",
        ("cursor", True): home / ".cursor" / "plugins" / "local" / "beacon",
        ("claude-code", False): root / ".claude" / "skills",
        ("claude-code", True): home / ".claude" / "skills",
        ("claude-cowork", False): root / ".claude" / "skills",
        ("claude-cowork", True): home / ".claude" / "skills",
        ("codex", False): root / ".codex" / "skills",
        ("codex", True): codex / "skills",
        ("pi", False): root / ".pi" / "skills",
        ("pi", True): home / ".pi" / "agent" / "skills",
        ("skills", False): root / "skills",
    }
    for (platform, user), path in expected.items():
        dest = platform_dest(
            platform,
            root=root,
            user=user,
            home=home,
            codex_home=codex if platform == "codex" and user else None,
        )
        assert dest.path == path
        if platform == "cursor" and user:
            assert dest.kind == "bundle"
        else:
            assert dest.kind == "skills"
        if platform == "claude-cowork":
            assert "does not scan" in dest.note
        else:
            assert dest.note == ""
    with pytest.raises(BeaconError) as caught:
        platform_dest("skills", root=root, user=True, home=home)
    assert caught.value.code == E_PLUGIN_SETUP
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("CODEX_HOME", " ")
    try:
        blank = platform_dest("codex", root=root, user=True, home=home)
    finally:
        monkeypatch.undo()
    assert blank.path == home / ".codex" / "skills"


def test_dry_run_writes_nothing(clean_env: None, tmp_path: Path) -> None:
    dest = tmp_path / "claude"
    result = install("claude-code", root=tmp_path, dest=dest, dry_run=True)
    assert result["dry_run"] is True
    assert result["mode"] == "copy"
    assert not dest.exists()
    skills = [row for row in result["actions"] if row["kind"] == "skill"]
    assert len(skills) == 8
    assert {row["op"] for row in skills} == {"copy"}
    assert any(row["kind"] == "index" for row in result["actions"])
    assert any(row["kind"] == "gate" for row in result["actions"])


def test_cli_dry_run_and_module_entry(clean_env: None, tmp_path: Path) -> None:
    dest = tmp_path / "out"
    runner = CliRunner()
    cli = runner.invoke(
        main,
        ["plugin", "install", "codex", "--dest", str(dest), "--dry-run", "--root", str(tmp_path)],
    )
    assert cli.exit_code == 0, cli.output
    assert not dest.exists()
    payload = json.loads(cli.output)
    assert payload["platform"] == "codex"
    other = tmp_path / "pi"
    code = plugin_main(["pi", "--dest", str(other), "--dry-run", "--root", str(tmp_path)])
    assert code == 0
    assert not other.exists()
    setup = runner.invoke(
        main,
        ["plugin-setup", "skills", "--dest", str(tmp_path / "skills-out"), "--dry-run", "--root", str(tmp_path)],
    )
    assert setup.exit_code == 0, setup.output
    unknown = runner.invoke(main, ["plugin", "install", "nope"])
    assert unknown.exit_code != 0
    plugins = runner.invoke(main, ["plugins", "--help"])
    assert plugins.exit_code == 0
    assert "drop-in" in plugins.output


def test_copy_and_link_then_refuse_drift(clean_env: None, tmp_path: Path) -> None:
    copied = tmp_path / "copied"
    first = install("claude-code", root=tmp_path, dest=copied, copy=True)
    assert first["mode"] == "copy"
    skill = copied / "beacon-scf-pin"
    assert skill.is_dir()
    assert not skill.is_symlink()
    source = find_plugin_root(_REPO) / "skills" / "beacon-scf-pin" / "SKILL.md"
    assert (skill / "SKILL.md").read_bytes() == source.read_bytes()
    index = (copied / "BEACON-SKILLS.md").read_text(encoding="utf-8")
    assert "2026.3" in index
    assert "beacon perch-receipt --mock" in index
    assert "unverified" in index
    for name in SKILL_NAMES:
        assert f"`{name}`" in index
    assert (copied / "PERCH-GATE.md").read_bytes() == (_REPO / "plugin" / "PERCH-GATE.md").read_bytes()
    again = install("claude-code", root=tmp_path, dest=copied, copy=True)
    assert {row["op"] for row in again["actions"]} == {"unchanged"}

    linked = tmp_path / "linked"
    install("cursor", root=tmp_path, dest=linked, link=True)
    link = linked / "beacon-overview"
    assert link.is_symlink()
    assert link.resolve() == (_REPO / "plugin" / "skills" / "beacon-overview").resolve()
    assert (link / "SKILL.md").read_text(encoding="utf-8").startswith("---\n")

    fresh = tmp_path / "fresh"
    (fresh / "beacon-local-mock").mkdir(parents=True)
    (fresh / "beacon-local-mock" / "SKILL.md").write_text("changed\n", encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        install("pi", root=tmp_path, dest=fresh, copy=True)
    assert caught.value.code == E_PLUGIN_SETUP
    assert not (fresh / "beacon-overview").exists()
    assert (fresh / "beacon-local-mock" / "SKILL.md").read_text(encoding="utf-8") == "changed\n"

    forced = install("pi", root=tmp_path, dest=fresh, copy=True, force=True)
    assert any(row["op"] == "copy" and row["kind"] == "skill" for row in forced["actions"])
    assert "name: beacon-local-mock" in (fresh / "beacon-local-mock" / "SKILL.md").read_text(encoding="utf-8")
    with pytest.raises(BeaconError) as switched:
        install("claude-code", root=tmp_path, dest=copied, link=True)
    assert switched.value.code == E_PLUGIN_SETUP
    assert not (copied / "beacon-scf-pin").is_symlink()
    install("claude-code", root=tmp_path, dest=copied, link=True, force=True)
    assert (copied / "beacon-scf-pin").is_symlink()
    with pytest.raises(BeaconError) as inside:
        install("skills", root=tmp_path, dest=_REPO / "plugin" / "skills", copy=True, dry_run=True)
    assert inside.value.code == E_PLUGIN_SETUP
    assert (_REPO / "plugin" / "skills" / "beacon-overview" / "SKILL.md").is_file()


def test_cowork_zip_user_bundle_and_flags(clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dest = tmp_path / "cowork"
    zips = tmp_path / "zips"
    dry = install("claude-cowork", root=tmp_path, dest=dest, zip_dir=zips, dry_run=True)
    assert "does not scan" in str(dry["note"])
    assert not dest.exists()
    assert not zips.exists()
    done = install("claude-cowork", root=tmp_path, dest=dest, copy=True, zip_dir=zips)
    archives = sorted(path.name for path in zips.glob("*.zip"))
    assert archives == sorted(f"{name}.zip" for name in SKILL_NAMES)
    with zipfile.ZipFile(zips / "beacon-overview.zip") as handle:
        assert handle.namelist() == ["beacon-overview/SKILL.md"]
        assert handle.read("beacon-overview/SKILL.md").startswith(b"---\n")
    assert done["platform"] == "claude-cowork"

    home = tmp_path / "home"
    project = tmp_path / "project"
    project.mkdir()
    bundle = install("cursor", root=project, user=True, home=home, copy=True)
    plugin_copy = home / ".cursor" / "plugins" / "local" / "beacon"
    assert Path(str(bundle["dest"])) == plugin_copy
    assert not plugin_copy.is_symlink()
    assert (plugin_copy / "skills" / "beacon-ci" / "SKILL.md").is_file()
    assert (plugin_copy / ".cursor-plugin" / "plugin.json").is_file()

    codex_home = tmp_path / "codex-home"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    codex = install("codex", root=project, user=True, home=home, copy=True)
    assert Path(str(codex["dest"])) == codex_home / "skills"
    assert (codex_home / "skills" / "beacon-ui" / "SKILL.md").is_file()

    with pytest.raises(BeaconError) as both:
        install("cursor", root=tmp_path, dest=tmp_path / "x", copy=True, link=True)
    assert both.value.code == E_PLUGIN_SETUP
    with pytest.raises(BeaconError) as zipped:
        install("cursor", root=tmp_path, dest=tmp_path / "y", zip_dir=tmp_path / "nope")
    assert zipped.value.code == E_PLUGIN_SETUP
    assert not (tmp_path / "nope").exists()
    assert not (tmp_path / "y").exists()
    fake = project / "plugin" / ".cursor-plugin"
    fake.mkdir(parents=True)
    (fake / "plugin.json").write_text('{"name": "beacon"}', encoding="utf-8")
    (project / "plugin" / "skills").mkdir()
    ignored = install("claude-code", root=project, dest=tmp_path / "from-package", copy=True, dry_run=True)
    assert Path(str(ignored["plugin_root"])) == _REPO / "plugin"
    monkeypatch.setenv("BEACON_PLUGIN_DIR", str(tmp_path / "missing"))
    with pytest.raises(BeaconError) as missing:
        install("skills", root=project, dest=tmp_path / "z", dry_run=True)
    assert missing.value.code == E_PLUGIN_SETUP


def test_index_and_written_files_omit_canary(clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PERCH_API_KEY", "super-secret-value")
    monkeypatch.setenv("BEACON_PLUGIN_SECRET_CANARY", "super-secret-value")
    skills = load_skills(find_plugin_root(_REPO))
    index = render_index(skills)
    assert "super-secret-value" not in index
    dest = tmp_path / "safe"
    result = install("skills", root=tmp_path, dest=dest, copy=True)
    blob = json.dumps(result)
    assert "super-secret-value" not in blob
    for path in dest.rglob("*"):
        if path.is_file():
            assert b"super-secret-value" not in path.read_bytes()
    assert os.environ["PERCH_API_KEY"] == "super-secret-value"


def _checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(_REPO / "plugin", repo / "plugin")
    monkeypatch.setenv("BEACON_PLUGIN_DIR", str(repo / "plugin"))
    return repo


def _deny_symlinks(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(self: Path, target: str | os.PathLike[str], target_is_directory: bool = False) -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(Path, "symlink_to", deny)


def test_install_help_names_pi_user_dir() -> None:
    runner = CliRunner()
    help_text = runner.invoke(main, ["plugin", "install", "--help"])
    assert help_text.exit_code == 0, help_text.output
    assert "~/.pi/agent/skills" in help_text.output
    assert "~/.pi/skills" not in help_text.output


def test_pi_user_install_writes_agent_skills(clean_env: None, tmp_path: Path) -> None:
    home = tmp_path / "home"
    project = tmp_path / "project"
    project.mkdir()
    result = install("pi", root=project, user=True, home=home)
    dest = home.resolve() / ".pi" / "agent" / "skills"
    assert Path(str(result["dest"])) == dest
    assert result["mode"] == "copy"
    assert (dest / "beacon-overview" / "SKILL.md").is_file()
    assert not (dest / "beacon-overview").is_symlink()
    assert not (home / ".pi" / "skills").exists()


def test_auto_mode_links_inside_checkout(clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _checkout(tmp_path, monkeypatch)
    planned = install("pi", root=repo, dry_run=True)
    assert planned["mode"] == "link"
    assert planned["dry_run"] is True
    assert not (repo / ".pi").exists()
    assert not any(path.name.startswith(".beacon-symlink-probe-") for path in repo.iterdir())
    result = install("pi", root=repo)
    dest = repo / ".pi" / "skills"
    assert Path(str(result["dest"])) == dest
    assert result["mode"] == "link"
    link = dest / "beacon-overview"
    assert link.is_symlink()
    plugin = Path(str(result["plugin_root"]))
    assert link.resolve() == (plugin / "skills" / "beacon-overview").resolve()
    assert not any(path.name.startswith(".beacon-symlink-probe-") for path in repo.rglob("*") if path.exists())


def test_explicit_copy_inside_checkout_stays_copy(clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _checkout(tmp_path, monkeypatch)
    dest = repo / ".claude" / "skills"
    result = install("claude-code", root=repo, dest=dest, copy=True)
    assert result["mode"] == "copy"
    skill = dest / "beacon-overview"
    assert skill.is_dir()
    assert not skill.is_symlink()
    assert (skill / "SKILL.md").is_file()


def test_auto_mode_copies_when_symlink_creation_fails(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _deny_symlinks(monkeypatch)
    repo = _checkout(tmp_path, monkeypatch)
    dest = repo / ".pi" / "skills"
    planned = install("pi", root=repo, dest=dest, dry_run=True)
    assert planned["mode"] == "copy"
    assert planned["dry_run"] is True
    assert not dest.exists()
    done = install("pi", root=repo, dest=dest)
    assert done["mode"] == "copy"
    skill = dest / "beacon-ci"
    assert skill.is_dir()
    assert not skill.is_symlink()
    assert (skill / "SKILL.md").is_file()
    assert (dest / "PERCH-GATE.md").is_file()
    assert not (dest / "PERCH-GATE.md").is_symlink()
    again = install("pi", root=repo, dest=dest)
    assert {row["op"] for row in again["actions"]} == {"unchanged"}


def test_explicit_link_fails_when_symlink_creation_fails(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _deny_symlinks(monkeypatch)
    repo = _checkout(tmp_path, monkeypatch)
    dest = repo / ".codex" / "skills"
    with pytest.raises(BeaconError) as caught:
        install("codex", root=repo, dest=dest, link=True)
    assert caught.value.code == E_PLUGIN_SETUP
    assert "Operation not permitted" in caught.value.message
    assert not (dest / "beacon-overview").exists()

    outside = tmp_path / "outside"
    with pytest.raises(BeaconError) as outside_caught:
        install("pi", root=tmp_path, dest=outside, link=True)
    assert outside_caught.value.code == E_PLUGIN_SETUP
    assert not (outside / "beacon-overview").exists()
