"""Plugin contract: FetcherSpec plus collect()."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class FetcherSpec:
    """Drop-in platform declaration (Paramify fetcher.yaml shape, Beacon-native)."""

    name: str
    version: str
    description: str
    category: str
    scf_targets: tuple[str, ...]
    tools: tuple[str, ...] = ()
    output_type: str = "json"
    secrets: tuple[str, ...] = ()


@dataclass
class CollectContext:
    target: str | None = None
    live: bool | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectResult:
    ok: bool
    mode: str
    payload: dict[str, Any]
    error: str | None = None
    # None uses FetcherSpec.scf_targets. () seals no control id.
    scf_targets: tuple[str, ...] | None = None

    @property
    def status(self) -> str:
        if self.mode == "live_failed":
            return "live_failed"
        if self.ok:
            return "ok"
        return "failed"


class Plugin(Protocol):
    spec: FetcherSpec

    def collect(self, ctx: CollectContext) -> CollectResult: ...


def covers_target(spec: FetcherSpec, target: str) -> bool:
    """True when the plugin overlaps the requested SCF control id."""
    want = target.strip().upper()
    for item in spec.scf_targets:
        have = item.strip().upper()
        if have == want:
            return True
        if want.startswith(have + ".") or have.startswith(want + "."):
            return True
        family_want = want.split("-", 1)[0]
        family_have = have.split("-", 1)[0]
        if have == family_want or want == family_have:
            return True
    return False
