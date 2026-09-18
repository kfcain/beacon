"""Builtin collector for the offline SCF 2026.2 catalog pin."""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal, NoReturn

from beacon.config import format_iso8601
from beacon.errors import BeaconError
from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec, covers_target
from beacon.scf.catalog_pin import (
    CATALOG_PROVENANCE,
    CATALOG_SCF_TARGET,
    PINNED_SCF_VERSION,
    CatalogPinResult,
    inspect_catalog_pin,
)

PLUGIN_NAME = "scf.catalog.offline"
SCHEMA_VERSION = "1.0"
CollectMode = Literal["fixture", "live_failed", "failed"]

DISCLAIMER = (
    "The SCF 2026.2 pin is the offline catalog (slim summary, families, index-meta, "
    "and workbook SHA-256). Live HackIDLE and GRCEngClub APIs stay at 2026.1.x. "
    "Those APIs are not authoritative. This collector does not vendor controls.json."
)


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value}")


def _now() -> str:
    return format_iso8601(dt.datetime.now(dt.timezone.utc))


def _bound_targets(spec: FetcherSpec) -> tuple[str, ...]:
    """Catalog evidence is always the plugin pin target. Do not inherit --target."""
    return spec.scf_targets


def _catalog_path_from(ctx: CollectContext) -> str | None:
    raw = ctx.extra.get("catalog_path")
    if raw is None or raw is False:
        return None
    return str(raw)


def _pin_payload(result: CatalogPinResult, *, mode: CollectMode, observed_at: str) -> dict[str, Any]:
    if mode not in ("fixture", "live_failed", "failed"):
        _never(mode)
    binding = result.scf_binding()
    pin = {
        "scf_version": result.scf_version,
        "catalog_root": str(result.catalog_root),
        "catalog_root_kind": result.catalog_root_kind,
        "workbook_sha256": result.workbook_sha256,
        "workbook_present": result.workbook_present,
        "file_sha256": dict(result.file_sha256),
        "counts": dict(result.counts),
        "family_codes": list(result.family_codes),
        "qts": {"family_code": "QTS", "control_count": result.qts_control_count},
        "live_api_authoritative": False,
        "provenance": CATALOG_PROVENANCE,
    }
    finding_status = "collected" if result.ok and mode == "fixture" else "failed"
    findings: list[dict[str, Any]]
    if result.ok and mode == "fixture":
        findings = [
            {
                "scf": CATALOG_SCF_TARGET,
                "check": f"{PLUGIN_NAME}.pin",
                "status": finding_status,
                "severity": "info",
                "scf_version": PINNED_SCF_VERSION,
                "pinned": True,
                "provenance": CATALOG_PROVENANCE,
            }
        ]
    else:
        findings = []
    return {
        "source": PLUGIN_NAME,
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "ok": bool(result.ok and mode == "fixture"),
        "observed_at": observed_at,
        "disclaimer": DISCLAIMER,
        "pin": pin,
        "catalog_pin": pin,
        "scf_binding": binding,
        "errors": list(result.errors),
        "observations": {
            "catalog": {
                "root": str(result.catalog_root),
                "kind": result.catalog_root_kind,
                "files": dict(result.file_sha256),
                "workbook_present": result.workbook_present,
            }
        },
        "findings": findings,
    }


class CatalogPlugin:
    spec = FetcherSpec(
        name=PLUGIN_NAME,
        version="0.1.0",
        description="Verify the offline SCF 2026.2 catalog pin (slim manifest + hashes).",
        category="scf",
        scf_targets=(CATALOG_SCF_TARGET,),
        tools=(),
    )

    def collect(self, ctx: CollectContext) -> CollectResult:
        observed_at = _now()
        targets = _bound_targets(self.spec)
        if ctx.target and not covers_target(self.spec, ctx.target):
            error = (
                f"{PLUGIN_NAME} binds only {CATALOG_SCF_TARGET}; "
                f"refusing target {ctx.target.strip().upper()}"
            )
            payload = {
                "source": PLUGIN_NAME,
                "schema_version": SCHEMA_VERSION,
                "mode": "failed",
                "ok": False,
                "observed_at": observed_at,
                "disclaimer": DISCLAIMER,
                "error": error,
                "errors": [error],
                "findings": [],
                "observations": {"catalog": {}},
                "scf_binding": {
                    "scf_version": "unpinned",
                    "scf_id": "",
                    "scf_ids": [],
                    "scf_family": "",
                    "erl_ids": [],
                    "framework_hops": [],
                    "pinned": False,
                    "provenance": CATALOG_PROVENANCE,
                },
            }
            return CollectResult(
                ok=False,
                mode="failed",
                payload=payload,
                error=error,
                scf_targets=targets,
            )
        if ctx.live is True:
            error = (
                "live HackIDLE/GRCEngClub APIs are not the SCF 2026.2 pin; "
                "use the offline catalog (BEACON_SCF_OFFLINE=1 / BEACON_SCF_CATALOG_PATH)"
            )
            payload = {
                "source": PLUGIN_NAME,
                "schema_version": SCHEMA_VERSION,
                "mode": "live_failed",
                "ok": False,
                "observed_at": observed_at,
                "disclaimer": DISCLAIMER,
                "error": error,
                "errors": [error],
                "findings": [],
                "observations": {"catalog": {"fetched": False}},
                "scf_binding": {
                    "scf_version": "unpinned",
                    "scf_id": "",
                    "scf_ids": [],
                    "scf_family": "",
                    "erl_ids": [],
                    "framework_hops": [],
                    "pinned": False,
                    "provenance": CATALOG_PROVENANCE,
                },
            }
            return CollectResult(
                ok=False,
                mode="live_failed",
                payload=payload,
                error=error,
                scf_targets=targets,
            )
        try:
            result = inspect_catalog_pin(_catalog_path_from(ctx))
        except BeaconError as exc:
            payload = {
                "source": PLUGIN_NAME,
                "schema_version": SCHEMA_VERSION,
                "mode": "failed",
                "ok": False,
                "observed_at": observed_at,
                "disclaimer": DISCLAIMER,
                "error": str(exc),
                "errors": [str(exc)],
                "findings": [],
                "observations": {"catalog": {}},
                "scf_binding": {
                    "scf_version": "unpinned",
                    "scf_id": "",
                    "scf_ids": [],
                    "scf_family": "",
                    "erl_ids": [],
                    "framework_hops": [],
                    "pinned": False,
                    "provenance": CATALOG_PROVENANCE,
                },
            }
            return CollectResult(
                ok=False,
                mode="failed",
                payload=payload,
                error=str(exc),
                scf_targets=targets,
            )
        mode: CollectMode = "fixture" if result.ok else "failed"
        payload = _pin_payload(result, mode=mode, observed_at=observed_at)
        error = "; ".join(result.errors) if not result.ok else None
        if error:
            payload["error"] = error
        return CollectResult(
            ok=result.ok,
            mode=mode,
            payload=payload,
            error=error,
            scf_targets=targets,
        )


PLUGIN = CatalogPlugin()
