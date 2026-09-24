"""HackIDLE SCF API client with offline fallback."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from beacon.config import SCF_VERSION, Settings
from beacon.errors import E_SCF, E_UNKNOWN_CONTROL, fail

OFFLINE_DIR = Path(__file__).resolve().parent / "offline"
CONTROL_ID_RE = re.compile(r"^[A-Z]{2,10}-\d+(\.\d+)*$")


def normalize_control_id(control_id: str) -> str:
    cid = control_id.strip().upper()
    if not CONTROL_ID_RE.match(cid):
        fail(E_UNKNOWN_CONTROL, f"invalid SCF control id {control_id!r}")
    return cid


def _safe_json_path(root: Path, control_id: str) -> Path:
    path = (root / f"{control_id}.json").resolve()
    if root.resolve() not in path.parents and path.parent != root.resolve():
        fail(E_SCF, "refusing path outside SCF store")
    return path


def _offline_control(control_id: str) -> dict[str, Any] | None:
    path = _safe_json_path(OFFLINE_DIR, control_id)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


@lru_cache(maxsize=1)
def offline_summary() -> dict[str, Any]:
    """Return the seed index for the offline control slices. Not the catalog pin."""
    return json.loads((OFFLINE_DIR / "summary.json").read_text(encoding="utf-8"))


def control_url(base: str, control_id: str) -> str:
    return f"{base.rstrip('/')}/api/controls/{control_id}.json"


def fetch_control(settings: Settings, control_id: str) -> dict[str, Any]:
    cid = normalize_control_id(control_id)
    if settings.scf_offline:
        data = _offline_control(cid)
        if data is None:
            fail(
                E_UNKNOWN_CONTROL,
                f"{cid} is not in the offline SCF bundle (BEACON_SCF_OFFLINE=1)",
            )
        return data
    cache_root = settings.cache_dir / "scf"
    cache_root.mkdir(parents=True, exist_ok=True)
    cache = _safe_json_path(cache_root, cid)
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    url = control_url(settings.scf_api_base, cid)
    try:
        response = httpx.get(url, timeout=20.0, follow_redirects=True)
    except Exception as exc:
        bundled = _offline_control(cid)
        if bundled is not None:
            return bundled
        fail(E_SCF, f"SCF API request failed: {exc}")
    if response.status_code == 404:
        fail(E_UNKNOWN_CONTROL, f"SCF control {cid} not found at {url}")
    if response.status_code >= 400:
        fail(E_SCF, f"SCF API HTTP {response.status_code} for {url}")
    try:
        data = response.json()
    except Exception as exc:
        fail(E_SCF, f"SCF API returned non-JSON: {exc}")
    cache.write_text(json.dumps(data), encoding="utf-8")
    return data


def summary(settings: Settings) -> dict[str, Any]:
    if settings.scf_offline:
        return offline_summary()
    url = f"{settings.scf_api_base.rstrip('/')}/api/summary.json"
    try:
        response = httpx.get(url, timeout=20.0, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return offline_summary()
    return data


def expected_version() -> str:
    return SCF_VERSION
