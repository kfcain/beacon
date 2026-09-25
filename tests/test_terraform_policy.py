"""Run Conftest against deploy/aws when the CLI is installed."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_S = 60


def _conftest() -> str:
    path = shutil.which("conftest")
    if path is None:
        if os.environ.get("BEACON_REQUIRE_POLICY_TESTS") == "1":
            pytest.fail("Conftest is required in CI")
        pytest.skip("conftest not installed; run make policy after installing Conftest")
    return path


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )


@pytest.fixture
def conftest_bin() -> str:
    return _conftest()


def test_conftest_verify(conftest_bin: str) -> None:
    result = _run([conftest_bin, "verify", "-p", "policy/terraform"])
    assert result.returncode == 0, result.stdout + result.stderr


def test_conftest_terraform_hcl(conftest_bin: str) -> None:
    tf_files = sorted((ROOT / "deploy" / "aws").glob("*.tf"))
    assert tf_files, "deploy/aws has no .tf files"
    result = _run(
        [
            conftest_bin,
            "test",
            "--combine",
            "--parser",
            "hcl2",
            "-p",
            "policy/terraform",
            "-o",
            "json",
            *[str(path) for path in tf_files],
        ]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    failures = 0
    for row in payload:
        raw = row.get("failures") or []
        failures += raw if isinstance(raw, int) else len(raw)
    assert failures == 0, result.stdout
