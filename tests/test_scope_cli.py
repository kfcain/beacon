"""Phase 1 assessment scope CLI: init, show, and hash."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.cli import main
from beacon.config import load_settings
from beacon.errors import E_SCOPE, E_UNKNOWN_SCOPE, E_UNSAFE_SCOPE_ID
from beacon.scope.document import ScopeDocument
from beacon.scope.store import STARTER_FRAMEWORK, STARTER_SYSTEM, init_scope, load_scope

SAFE_ID = "prod-commercial"


def _invoke(args: list[str]):
    return CliRunner().invoke(main, args)


def test_scope_init_show_hash_round_trip(beacon_home: Path):
    init_res = _invoke(["scope", "init", "--id", SAFE_ID])
    assert init_res.exit_code == 0, init_res.output
    show_res = _invoke(["scope", "show", "--id", SAFE_ID])
    assert show_res.exit_code == 0, show_res.output
    hash_res = _invoke(["scope", "hash", "--id", SAFE_ID])
    assert hash_res.exit_code == 0, hash_res.output

    path = beacon_home / "scopes" / f"{SAFE_ID}.json"
    document = ScopeDocument.model_validate_json(path.read_text(encoding="utf-8"))
    shown = ScopeDocument.model_validate(json.loads(show_res.output))
    assert shown == document
    assert document.schema_version == 1
    assert document.scope_id == SAFE_ID
    assert document.catalog_pin_version == "2026.3"
    assert document.frameworks == (STARTER_FRAMEWORK,)
    assert document.boundary.systems == (STARTER_SYSTEM,)
    assert hash_res.output.strip() == document.content_sha256()
    assert shown.content_sha256() == document.content_sha256()
    raw = path.read_text(encoding="utf-8").lower()
    assert "private key" not in raw
    assert "aws_secret" not in raw
    assert "password" not in raw


def test_scope_init_refuses_a_second_write(beacon_home: Path):
    first = _invoke(["scope", "init", "--id", SAFE_ID])
    assert first.exit_code == 0
    path = beacon_home / "scopes" / f"{SAFE_ID}.json"
    before = path.read_bytes()
    second = _invoke(["scope", "init", "--id", SAFE_ID])
    assert second.exit_code == 2
    assert E_SCOPE in second.output
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "scope_id",
    ["../escape", "foo/bar", "foo\\bar", "..", ".hidden", "-bad", "has space", "", "a" * 256],
)
def test_scope_commands_reject_unsafe_id(beacon_home: Path, scope_id: str):
    for command in ("init", "show", "hash"):
        result = _invoke(["scope", command, "--id", scope_id])
        assert result.exit_code == 2
        assert E_UNSAFE_SCOPE_ID in result.output
    assert [path for path in beacon_home.rglob("*") if path.name != ".workspace.lock"] == []
    outside = beacon_home.parent / "escape.json"
    assert not outside.exists()


def test_scope_show_and_hash_fail_closed_when_file_is_missing(beacon_home: Path):
    for command in ("show", "hash"):
        result = _invoke(["scope", command, "--id", "not-created"])
        assert result.exit_code == 2
        assert E_UNKNOWN_SCOPE in result.output
    init_scope(load_settings(), SAFE_ID)
    path = beacon_home / "scopes" / f"{SAFE_ID}.json"
    path.unlink()
    missing = _invoke(["scope", "show", "--id", SAFE_ID])
    assert missing.exit_code == 2
    assert E_UNKNOWN_SCOPE in missing.output
    missing_hash = _invoke(["scope", "hash", "--id", SAFE_ID])
    assert missing_hash.exit_code == 2
    assert E_UNKNOWN_SCOPE in missing_hash.output


def test_scope_load_fails_closed_on_id_mismatch(beacon_home: Path):
    init_scope(load_settings(), SAFE_ID)
    path = beacon_home / "scopes" / f"{SAFE_ID}.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    body["scope_id"] = "other-scope"
    path.write_text(json.dumps(body), encoding="utf-8")
    result = _invoke(["scope", "hash", "--id", SAFE_ID])
    assert result.exit_code == 2
    assert E_SCOPE in result.output
    with pytest.raises(Exception) as caught:
        load_scope(load_settings(), SAFE_ID)
    assert getattr(caught.value, "code", "") == E_SCOPE
