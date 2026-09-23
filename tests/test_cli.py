"""CLI entry points."""

from __future__ import annotations

from click.testing import CliRunner

from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import seal_payload
from beacon.errors import E_NO_CHECKPOINT
from beacon.workspace import init_workspace


def test_cli_init_seed_check(beacon_home):
    runner = CliRunner()
    init_res = runner.invoke(main, ["init"])
    assert init_res.exit_code == 0
    seed_res = runner.invoke(main, ["seed"])
    assert seed_res.exit_code == 0
    check_res = runner.invoke(main, ["check"])
    assert check_res.exit_code == 0
    plugins = runner.invoke(main, ["plugins"])
    assert "aws.inspector" in plugins.output
    assert "aws.lake.logs" in plugins.output
    assert "azure.inspector" in plugins.output
    assert "gcp.inspector" in plugins.output
    assert "scf.catalog.offline" in plugins.output


def test_cli_check_prints_e_no_checkpoint(initialized):
    seal_payload(
        load_settings(),
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-01"],
        payload={"x": 1},
    )
    runner = CliRunner()
    result = runner.invoke(main, ["check"])
    assert result.exit_code != 0
    assert E_NO_CHECKPOINT in result.output


def test_cli_collect_target(initialized):
    runner = CliRunner()
    result = runner.invoke(main, ["collect", "--target", "IAC-01", "--fixture"])
    assert result.exit_code == 0
    assert "aws.inspector" in result.output
    status = runner.invoke(main, ["status"])
    assert status.exit_code == 0
    assert "recorder_fingerprint" in status.output
