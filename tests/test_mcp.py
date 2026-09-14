"""MCP tools are named beacon_*."""

from __future__ import annotations

from beacon import MCP_TOOL_PREFIX
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
    for overlay_id in ("KSI-CNA-OFA", "KSI-PIY-RES", "SA-09(07)", "SC-12(06)"):
        assert lookup["scf_binding"]["overlay_unmapped"][overlay_id] == []
