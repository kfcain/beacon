"""Paths and ``BEACON_*`` environment configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from beacon import DATA_DIR_NAME

DEFAULT_SCF_API_BASE = "https://hackidle.github.io/scf-api/"
SCF_VERSION = "2026.1.1"


def _truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env(name: str, default: str | None = None) -> str | None:
    """Read ``BEACON_<name>``. ``name`` is the suffix after the prefix."""
    return os.environ.get(f"BEACON_{name}", default)


DEFAULT_DDB_TABLE = "beacon-artifact-index"
DEFAULT_OBJECT_LOCK_MODE = "GOVERNANCE"
DEFAULT_OBJECT_LOCK_DAYS = 365
KMS_ALIAS_BEACON_EVIDENCE = "alias/beacon-evidence"


def _int_env(name: str, default: int) -> int:
    raw = env(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    home: Path
    scf_api_base: str
    scf_offline: bool
    plugin_path: tuple[Path, ...]
    tsa_url: str | None
    force_fixture: bool
    s3_bucket: str | None
    s3_prefix: str
    kms_key_arn: str | None
    ddb_table: str | None
    object_lock_mode: str
    object_lock_days: int
    tenant_id: str | None
    workspace_id: str | None
    require_remote: bool

    @property
    def keys_dir(self) -> Path:
        return self.home / "keys"

    @property
    def chain_path(self) -> Path:
        return self.home / "chain" / "records.jsonl"

    @property
    def checkpoints_path(self) -> Path:
        return self.home / "chain" / "checkpoints.jsonl"

    @property
    def evidence_dir(self) -> Path:
        return self.home / "evidence"

    @property
    def export_dir(self) -> Path:
        return self.home / "export"

    @property
    def cache_dir(self) -> Path:
        return self.home / "cache"


def data_home(cwd: Path | None = None) -> Path:
    override = env("HOME") or env("DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    root = cwd if cwd is not None else Path.cwd()
    return (root / DATA_DIR_NAME).resolve()


def load_settings(cwd: Path | None = None) -> Settings:
    home = data_home(cwd)
    plugin_raw = env("PLUGIN_PATH") or ""
    plugin_path = tuple(Path(p).expanduser() for p in plugin_raw.split(os.pathsep) if p.strip())
    tsa_url = env("TSA_URL")
    bucket = (env("S3_BUCKET") or "").strip() or None
    prefix = (env("S3_PREFIX") or "").strip().strip("/")
    kms_key = (env("KMS_KEY_ARN") or "").strip() or None
    table = (env("DDB_TABLE") or "").strip() or None
    if bucket and not table:
        table = DEFAULT_DDB_TABLE
    if bucket and not kms_key:
        kms_key = KMS_ALIAS_BEACON_EVIDENCE
    lock_mode = (env("OBJECT_LOCK_MODE") or DEFAULT_OBJECT_LOCK_MODE).strip().upper()
    tenant = (env("TENANT_ID") or "").strip() or None
    workspace = (env("WORKSPACE_ID") or "").strip() or None
    return Settings(
        home=home,
        scf_api_base=(env("SCF_API_BASE") or DEFAULT_SCF_API_BASE).rstrip("/") + "/",
        scf_offline=_truthy(env("SCF_OFFLINE")),
        plugin_path=plugin_path,
        tsa_url=tsa_url if tsa_url else None,
        force_fixture=_truthy(env("FORCE_FIXTURE")),
        s3_bucket=bucket,
        s3_prefix=prefix,
        kms_key_arn=kms_key,
        ddb_table=table,
        object_lock_mode=lock_mode,
        object_lock_days=_int_env("OBJECT_LOCK_DAYS", DEFAULT_OBJECT_LOCK_DAYS),
        tenant_id=tenant,
        workspace_id=workspace,
        require_remote=_truthy(env("REQUIRE_REMOTE")),
    )


def ensure_layout(settings: Settings) -> None:
    for path in (
        settings.home,
        settings.keys_dir,
        settings.chain_path.parent,
        settings.evidence_dir,
        settings.export_dir,
        settings.cache_dir,
        settings.cache_dir / "scf",
    ):
        path.mkdir(parents=True, exist_ok=True)
    if not settings.chain_path.exists():
        settings.chain_path.touch()
    if not settings.checkpoints_path.exists():
        settings.checkpoints_path.touch()
