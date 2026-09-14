"""MCP tools are named beacon_*."""

from __future__ import annotations

import json

from beacon import MCP_TOOL_PREFIX
from beacon.config import load_settings
from beacon.mcp.server import TOOLS, call_tool, handle_message, list_tools


def test_mcp_tool_names_use_beacon_prefix():
    names = [item["name"] for item in list_tools()]
    assert names
    assert all(name.startswith(MCP_TOOL_PREFIX) for name in names)
    assert f"{MCP_TOOL_PREFIX}collect" in names
    assert f"{MCP_TOOL_PREFIX}check" in names
    assert set(TOOLS) == set(names)


def test_mcp_initialize_and_tools_list():
    reply = handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert reply is not None
    assert reply["result"]["serverInfo"]["name"] == "beacon"
    listed = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed is not None
    tools = listed["result"]["tools"]
    assert any(item["name"] == "beacon_scf_lookup" for item in tools)


def test_mcp_collect_and_check(initialized):
    collected = call_tool("beacon_collect", {"target": "CRY-05", "live": False})
    assert "runs" in collected
    checked = call_tool("beacon_check", {})
    assert checked.get("ok") is True
    lookup = call_tool("beacon_scf_lookup", {"control_id": "IAC-01"})
    assert lookup["control_id"] == "IAC-01"
    assert lookup["scf_version"] == "2026.2"
    assert lookup["scf_binding"]["scf_family"] == "IAC"
    assert lookup["scf_binding"]["pinned"] is True
    for overlay_id in ("KSI-CNA-OFA", "KSI-PIY-RES", "SA-09(07)", "SC-12(06)"):
        assert lookup["scf_binding"]["overlay_unmapped"][overlay_id] == []


def test_mcp_lookup_cached_control_outside_pin(beacon_home, monkeypatch):
    monkeypatch.setenv("BEACON_SCF_OFFLINE", "0")
    settings = load_settings()
    cache = settings.cache_dir / "scf"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "GOV-01.json").write_text(
        json.dumps(
            {
                "control_id": "GOV-01",
                "title": "Governance",
                "family": "GOV",
                "scf_version": "2026.1.1",
                "evidence_requests": ["E-GOV-01"],
                "crosswalks": {},
            }
        ),
        encoding="utf-8",
    )
    lookup = call_tool("beacon_scf_lookup", {"control_id": "GOV-01"})
    assert lookup["control_id"] == "GOV-01"
    assert lookup["scf_version"] == "2026.1.1"
    assert lookup["scf_binding"]["pinned"] is False
    assert lookup["scf_binding"]["scf_id"] == "GOV-01"
