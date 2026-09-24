"""Shared cloud inspector plugin class for AWS, Azure, and GCP."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec

CloudName = Literal["aws", "azure", "gcp"]

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"

_NO_CREDS_MARKERS = (
    "unable to locate credentials",
    "nocredentialproviders",
    "please run az login",
    "az login",
    "no active account",
    "there are no credentials",
    "not logged in",
    "could not find default credentials",
    "application default credentials",
)

_LIVE_FAIL_MARKERS = (
    "expiredtoken",
    "expired token",
    "accessdenied",
    "invalidclienttokenid",
    "reauthentication needed",
)


@dataclass(frozen=True)
class CloudProfile:
    cloud: CloudName
    name: str
    tool: str
    probe: tuple[str, ...]
    live_commands: tuple[tuple[str, ...], ...]
    scf_targets: tuple[str, ...]
    description: str


AWS_PROFILE = CloudProfile(
    cloud="aws",
    name="aws.inspector",
    tool="aws",
    probe=("aws", "sts", "get-caller-identity"),
    live_commands=(
        ("aws", "iam", "get-account-password-policy"),
        ("aws", "iam", "get-account-summary"),
        ("aws", "s3api", "list-buckets"),
        ("aws", "ec2", "get-ebs-encryption-by-default"),
        ("aws", "cloudtrail", "describe-trails"),
    ),
    scf_targets=("IAC-02", "CRY-07"),
    description="AWS inspector: IAM, S3 encryption, EBS default encryption, CloudTrail.",
)

AZURE_PROFILE = CloudProfile(
    cloud="azure",
    name="azure.inspector",
    tool="az",
    probe=("az", "account", "show"),
    live_commands=(
        ("az", "ad", "signed-in-user", "show"),
        ("az", "storage", "account", "list", "-o", "json"),
        ("az", "keyvault", "list", "-o", "json"),
        ("az", "monitor", "diagnostic-settings", "subscription", "list", "-o", "json"),
    ),
    scf_targets=("IAC-02", "CRY-07"),
    description="Azure inspector: Entra identity, storage encryption, Key Vault.",
)

GCP_PROFILE = CloudProfile(
    cloud="gcp",
    name="gcp.inspector",
    tool="gcloud",
    probe=("gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"),
    live_commands=(
        ("gcloud", "projects", "get-iam-policy", "--format=json"),
        ("gcloud", "storage", "buckets", "list", "--format=json"),
        ("gcloud", "kms", "keys", "list", "--format=json"),
        ("gcloud", "logging", "sinks", "list", "--format=json"),
    ),
    scf_targets=("IAC-02", "CRY-07"),
    description="GCP inspector: IAM, Cloud Storage encryption, KMS, audit sinks.",
)


def _run(cmd: tuple[str, ...], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(cmd),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _looks_like_missing_creds(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in _NO_CREDS_MARKERS)


def _looks_like_live_failure(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in _LIVE_FAIL_MARKERS)


class CloudInspectorPlugin:
    """One plugin class. AWS, Azure, and GCP are instances with a cloud profile."""

    def __init__(self, profile: CloudProfile) -> None:
        self.profile = profile
        self.spec = FetcherSpec(
            name=profile.name,
            version="0.1.0",
            description=profile.description,
            category=profile.cloud,
            scf_targets=profile.scf_targets,
            tools=(profile.tool,),
        )

    def collect(self, ctx: CollectContext) -> CollectResult:
        force_fixture = bool(ctx.extra.get("force_fixture"))
        if ctx.live is True:
            force_fixture = False
        if force_fixture or ctx.live is False:
            return self._fixture_result(ctx, reason="forced_fixture")
        probe = self._probe()
        if probe != "ok":
            if ctx.live is True:
                return self._live_failed("live requested but credentials are not available")
            if probe == "no_creds":
                return self._fixture_result(ctx, reason="no_credentials")
            return self._live_failed("live credential or API probe failed")
        try:
            payload = self._live_collect(ctx)
        except Exception as exc:
            return self._live_failed(str(exc))
        return CollectResult(
            ok=True,
            mode="live",
            payload=payload,
            scf_targets=self._targets_for(ctx),
        )

    def _targets_for(self, ctx: CollectContext) -> tuple[str, ...]:
        if ctx.target:
            return (ctx.target.upper(),)
        return self.spec.scf_targets

    def _probe(self) -> str:
        if shutil.which(self.profile.tool) is None:
            return "no_creds"
        try:
            proc = _run(self.profile.probe)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            if isinstance(exc, FileNotFoundError):
                return "no_creds"
            return "live_failed"
        combined = f"{proc.stdout}\n{proc.stderr}"
        if proc.returncode != 0:
            if _looks_like_live_failure(combined):
                return "live_failed"
            if _looks_like_missing_creds(combined):
                return "no_creds"
            return "live_failed"
        if self.profile.cloud == "gcp" and not proc.stdout.strip():
            return "no_creds"
        return "ok"

    def _live_collect(self, ctx: CollectContext) -> dict:
        observations: list[dict] = []
        for cmd in self.profile.live_commands:
            proc = _run(cmd)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"live command failed ({self.profile.tool}): {' '.join(cmd)}: {proc.stderr.strip() or proc.stdout.strip()}"
                )
            body: object
            text = proc.stdout.strip()
            try:
                body = json.loads(text) if text else {}
            except json.JSONDecodeError:
                body = {"raw": text}
            observations.append({"cmd": list(cmd), "ok": True, "body": body})
        return {
            "source": self.spec.name,
            "cloud": self.profile.cloud,
            "mode": "live",
            "target": ctx.target,
            "identity_tool": self.profile.tool,
            "observations": observations,
            "findings": self._findings_from_live(ctx, observations),
        }

    def _findings_from_live(self, ctx: CollectContext, observations: list[dict]) -> list[dict]:
        targets = self._targets_for(ctx)
        findings = []
        for target in targets:
            findings.append(
                {
                    "scf": target,
                    "check": f"{self.profile.cloud}.live",
                    "status": "collected",
                    "severity": "info",
                    "observation_count": len(observations),
                }
            )
        return findings

    def _fixture_result(self, ctx: CollectContext, reason: str) -> CollectResult:
        payload = json.loads((FIXTURE_DIR / f"{self.profile.cloud}.inspector.json").read_text(encoding="utf-8"))
        payload = dict(payload)
        payload["mode"] = "fixture"
        payload["fixture_reason"] = reason
        payload["target"] = ctx.target
        if ctx.target:
            want = ctx.target.upper()
            payload["findings"] = [
                item
                for item in payload.get("findings", [])
                if str(item.get("scf", "")).upper() == want
                or str(item.get("scf", "")).upper().startswith(want + ".")
            ]
        return CollectResult(
            ok=True,
            mode="fixture",
            payload=payload,
            scf_targets=self._targets_for(ctx),
        )

    def _live_failed(self, error: str) -> CollectResult:
        payload = {
            "source": self.spec.name,
            "cloud": self.profile.cloud,
            "mode": "live_failed",
            "ok": False,
            "error": error,
            "findings": [],
        }
        return CollectResult(
            ok=False,
            mode="live_failed",
            payload=payload,
            error=error,
            scf_targets=self.spec.scf_targets,
        )


def builtin_plugins() -> tuple[CloudInspectorPlugin, CloudInspectorPlugin, CloudInspectorPlugin]:
    return (
        CloudInspectorPlugin(AWS_PROFILE),
        CloudInspectorPlugin(AZURE_PROFILE),
        CloudInspectorPlugin(GCP_PROFILE),
    )
