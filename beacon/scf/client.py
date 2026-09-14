"""SCF catalog client. Offline 2026.2 fixtures are the pin. Live APIs are fallback only."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from beacon.config import SCF_VERSION, Settings
from beacon.errors import E_CONTROL_MISMATCH, E_SCF, E_UNKNOWN_CONTROL, fail

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


def _require_control_id(data: Any, control_id: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        fail(E_SCF, f"SCF control {control_id} payload is not an object")
    got = str(data.get("control_id") or "").strip().upper()
    if got != control_id:
        fail(E_CONTROL_MISMATCH, f"SCF control {control_id} payload has control_id {got!r}")
    return data


def _load_control_json(path: Path, control_id: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(E_SCF, f"SCF control {control_id} JSON is invalid: {exc}")
    return _require_control_id(data, control_id)


def _offline_control(control_id: str) -> dict[str, Any] | None:
    path = _safe_json_path(OFFLINE_DIR, control_id)
    if path.exists():
        return _load_control_json(path, control_id)
    return None


def list_offline_control_ids() -> list[str]:
    ids = []
    for path in sorted(OFFLINE_DIR.glob("*.json")):
        stem = path.stem
        if stem in {"summary", "PIN"}:
            continue
        ids.append(stem)
    return ids


@lru_cache(maxsize=1)
def offline_summary() -> dict[str, Any]:
    return json.loads((OFFLINE_DIR / "summary.json").read_text(encoding="utf-8"))


def control_url(base: str, control_id: str) -> str:
    return f"{base.rstrip('/')}/api/controls/{control_id}.json"


def try_offline_control(control_id: str) -> dict[str, Any] | None:
    """Return the 2026.2 pin file for one control, or None when the slice omits it."""
    return _offline_control(normalize_control_id(control_id))


def fetch_pinned_control(control_id: str) -> dict[str, Any]:
    """Load one control from the SCF 2026.2 offline pin. Never use the live API."""
    cid = normalize_control_id(control_id)
    data = _offline_control(cid)
    if data is None:
        fail(
            E_UNKNOWN_CONTROL,
            f"{cid} is not in the SCF 2026.2 offline pin",
        )
    return data


def fetch_control(settings: Settings, control_id: str) -> dict[str, Any]:
    cid = normalize_control_id(control_id)
    bundled = _offline_control(cid)
    if bundled is not None:
        return bundled
    if settings.scf_offline:
        fail(
            E_UNKNOWN_CONTROL,
            f"{cid} is not in the offline SCF 2026.2 bundle (BEACON_SCF_OFFLINE=1)",
        )
    cache_root = settings.cache_dir / "scf"
    cache_root.mkdir(parents=True, exist_ok=True)
    cache = _safe_json_path(cache_root, cid)
    if cache.exists():
        return _load_control_json(cache, cid)
    url = control_url(settings.scf_api_base, cid)
    try:
        response = httpx.get(url, timeout=20.0, follow_redirects=True)
    except Exception as exc:
        fail(E_SCF, f"SCF API request failed: {exc}")
    if response.status_code == 404:
        fail(E_UNKNOWN_CONTROL, f"SCF control {cid} not found at {url}")
    if response.status_code >= 400:
        fail(E_SCF, f"SCF API HTTP {response.status_code} for {url}")
    try:
        data = response.json()
    except Exception as exc:
        fail(E_SCF, f"SCF API returned non-JSON: {exc}")
    if not isinstance(data, dict):
        fail(E_SCF, f"SCF API returned a non-object for {url}")
    _require_control_id(data, cid)
    cache.write_text(json.dumps(data), encoding="utf-8")
    return data


def summary(_settings: Settings) -> dict[str, Any]:
    # The pin is the offline 2026.2 bundle. Live HackIDLE/club APIs are not the pin.
    return offline_summary()


def expected_version() -> str:
    return SCF_VERSION
