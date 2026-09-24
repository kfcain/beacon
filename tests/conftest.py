"""Shared pytest fixtures. Tests run with BEACON_SCF_OFFLINE=1."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from beacon.config import load_settings
from beacon.workspace import init_workspace


@pytest.fixture
def beacon_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / ".beacon"
    monkeypatch.setenv("BEACON_HOME", str(home))
    monkeypatch.setenv("BEACON_SCF_OFFLINE", "1")
    monkeypatch.delenv("BEACON_PLUGIN_PATH", raising=False)
    monkeypatch.delenv("BEACON_TSA_URL", raising=False)
    monkeypatch.delenv("BEACON_FORCE_FIXTURE", raising=False)
    monkeypatch.delenv("BEACON_SCF_API_BASE", raising=False)
    monkeypatch.delenv("BEACON_SCF_CATALOG_PATH", raising=False)
    for key in (
        "BEACON_S3_BUCKET",
        "BEACON_S3_PREFIX",
        "BEACON_KMS_KEY_ARN",
        "BEACON_DDB_TABLE",
        "BEACON_OBJECT_LOCK_MODE",
        "BEACON_OBJECT_LOCK_DAYS",
        "BEACON_TENANT_ID",
        "BEACON_WORKSPACE_ID",
        "BEACON_REQUIRE_REMOTE",
        "BEACON_PACK_TYPE",
        "BEACON_TRUST_CENTER_EXPORT",
        "BEACON_REQUIRE_SCOPE",
        "BEACON_LOGS_BUCKET",
        "BEACON_LOGS_ACCESS_PREFIX",
        "BEACON_LOGS_CLOUDTRAIL_PREFIX",
        "BEACON_LOGS_MAX_OBJECTS",
        "BEACON_LOGS_MAX_BYTES",
    ):
        monkeypatch.delenv(key, raising=False)
    os.environ["BEACON_HOME"] = str(home)
    os.environ["BEACON_SCF_OFFLINE"] = "1"
    return home


@pytest.fixture
def initialized(beacon_home: Path) -> Path:
    init_workspace(load_settings())
    return beacon_home
