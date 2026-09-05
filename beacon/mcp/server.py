"""MCP stdio server. Tools are named ``beacon_*``."""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

from beacon import MCP_TOOL_PREFIX, __version__
from beacon.config import load_settings
from beacon.crypto.witness import check_chain
from beacon.errors import BeaconError
from beacon.plugins.loader import load_plugins
from beacon.plugins.spec import CollectContext
from beacon.push import write_pack
from beacon.scf.client import fetch_control
from beacon.scf.engine import collect_all, collect_named, collect_target
from beacon.workspace import freshness, init_workspace, seed_workspace, system_status, validation

ToolFn = Callable[[dict[str, Any]], dict[str, Any]]


def _tool_error(exc: BaseException) -> dict[str, Any]:
    code = getattr(exc, "code", "E_ERROR")
    return {"ok": False, "code": code, "error": str(exc)}


def tool_beacon_status(_args: dict[str, Any]) -> dict[str, Any]:
    return system_status(load_settings())


def tool_beacon_init(_args: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, **init_workspace(load_settings())}


def tool_beacon_seed(_args: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, **seed_workspace(load_settings())}


def tool_beacon_check(_args: dict[str, Any]) -> dict[str, Any]:
    return check_chain(load_settings())


def tool_beacon_collect(args: dict[str, Any]) -> dict[str, Any]:
    settings = load_settings()
    target = args.get("target")
    plugin = args.get("plugin")
    live = args.get("live")
    ctx = CollectContext(target=target, live=live)
    if plugin:
        return collect_named(settings, str(plugin), ctx, checkpoint=True)
    if target:
        return collect_target(settings, str(target), ctx, checkpoint=True)
    return collect_all(settings, ctx, checkpoint=True)


def tool_beacon_plugins(_args: dict[str, Any]) -> dict[str, Any]:
    settings = load_settings()
    return {
        "plugins": [
            {
                "name": plugin.spec.name,
                "scf_targets": list(plugin.spec.scf_targets),
                "tools": list(plugin.spec.tools),
            }
            for plugin in load_plugins(settings).values()
        ]
    }


def tool_beacon_freshness(_args: dict[str, Any]) -> dict[str, Any]:
    return {"items": freshness(load_settings())}


def tool_beacon_scf_lookup(args: dict[str, Any]) -> dict[str, Any]:
    control_id = str(args.get("control_id") or args.get("target") or "")
    if not control_id:
        return {"ok": False, "code": "E_UNKNOWN_CONTROL", "error": "control_id is required"}
    control = fetch_control(load_settings(), control_id)
    return {
        "control_id": control.get("control_id"),
        "title": control.get("title"),
        "family": control.get("family"),
        "description": control.get("description"),
        "scf_question": control.get("scf_question"),
    }


def tool_beacon_push(args: dict[str, Any]) -> dict[str, Any]:
    path = write_pack(load_settings(), None)
    return {"ok": True, "path": str(path)}


def tool_beacon_validation(_args: dict[str, Any]) -> dict[str, Any]:
    return validation(load_settings())


TOOLS: dict[str, tuple[str, dict[str, Any], ToolFn]] = {
    f"{MCP_TOOL_PREFIX}status": (
        "Show Beacon workspace status, key fingerprints, and chain coverage.",
        {"type": "object", "properties": {}},
        tool_beacon_status,
    ),
    f"{MCP_TOOL_PREFIX}init": (
        "Initialize `.beacon/` with distinct recorder and witness keys plus a local TSA.",
        {"type": "object", "properties": {}},
        tool_beacon_init,
    ),
    f"{MCP_TOOL_PREFIX}seed": (
        "Seal builtin inspector fixtures through the witness chain and checkpoint.",
        {"type": "object", "properties": {}},
        tool_beacon_seed,
    ),
    f"{MCP_TOOL_PREFIX}check": (
        "Verify the witness chain. Fails closed with E_NO_CHECKPOINT when coverage is missing.",
        {"type": "object", "properties": {}},
        tool_beacon_check,
    ),
    f"{MCP_TOOL_PREFIX}collect": (
        "Collect evidence for a plugin or SCF target and seal a checkpoint.",
        {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "SCF control id such as IAC-01 or CRY-05"},
                "plugin": {"type": "string", "description": "Plugin name such as aws.inspector"},
                "live": {"type": "boolean"},
            },
        },
        tool_beacon_collect,
    ),
    f"{MCP_TOOL_PREFIX}plugins": (
        "List builtin and drop-in Beacon plugins.",
        {"type": "object", "properties": {}},
        tool_beacon_plugins,
    ),
    f"{MCP_TOOL_PREFIX}freshness": (
        "Latest sealed evidence timestamp per plugin.",
        {"type": "object", "properties": {}},
        tool_beacon_freshness,
    ),
    f"{MCP_TOOL_PREFIX}scf_lookup": (
        "Fetch one SCF control from the HackIDLE API or the offline bundle.",
        {
            "type": "object",
            "properties": {
                "control_id": {"type": "string"},
                "target": {"type": "string"},
            },
        },
        tool_beacon_scf_lookup,
    ),
    f"{MCP_TOOL_PREFIX}push": (
        "Export a sealed evidence pack with public keys only.",
        {"type": "object", "properties": {}},
        tool_beacon_push,
    ),
    f"{MCP_TOOL_PREFIX}validation": (
        "Run chain validation and return OK or E_NO_CHECKPOINT.",
        {"type": "object", "properties": {}},
        tool_beacon_validation,
    ),
}


def list_tools() -> list[dict[str, Any]]:
    return [
        {"name": name, "description": desc, "inputSchema": schema}
        for name, (desc, schema, _fn) in TOOLS.items()
    ]


def call_tool(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    if name not in TOOLS:
        return {"ok": False, "error": f"unknown tool {name}"}
    _desc, _schema, fn = TOOLS[name]
    try:
        return fn(arguments or {})
    except BeaconError as exc:
        return _tool_error(exc)


def _rpc_result(rpc_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _rpc_error(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def handle_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    method = msg.get("method")
    rpc_id = msg.get("id")
    if method == "initialize":
        return _rpc_result(
            rpc_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "beacon", "version": __version__},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _rpc_result(rpc_id, {"tools": list_tools()})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        payload = call_tool(str(name), arguments)
        text = json.dumps(payload, default=str)
        is_error = isinstance(payload, dict) and payload.get("ok") is False
        return _rpc_result(
            rpc_id,
            {"content": [{"type": "text", "text": text}], "isError": is_error},
        )
    if method == "ping":
        return _rpc_result(rpc_id, {})
    if rpc_id is None:
        return None
    return _rpc_error(rpc_id, -32601, f"method not found: {method}")


def run_stdio() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(_rpc_error(None, -32700, "parse error")) + "\n")
            sys.stdout.flush()
            continue
        reply = handle_message(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
