"""Custody tag registry. A tag is metadata. It is not a claim word."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, NoReturn

from beacon.assurance.pin_ids import SEEDED_CONTROL_IDS, framework_id_on_pin
from beacon.scope.document import EVIDENCE_KINDS, SCOPE_ID_RE

Namespace = Literal[
    "platform",
    "evidence",
    "owner",
    "automation",
    "framework",
    "control",
    "risk",
]

NAMESPACES: tuple[Namespace, ...] = (
    "platform",
    "evidence",
    "owner",
    "automation",
    "framework",
    "control",
    "risk",
)

# Platforms that already have a builtin collector. No other platform is registered.
PLATFORM_VALUES: frozenset[str] = frozenset({"aws", "azure", "gcp"})

# Existing evidence kinds, plus the policy tip tag from the assurance-stack ADR.
EVIDENCE_VALUES: frozenset[str] = frozenset({*EVIDENCE_KINDS, "policy"})

# Method class labels for ledger counts. These words are not claim words.
AUTOMATION_VALUES: frozenset[str] = frozenset({"automated", "manual"})

# The pin summary counts risks and does not list risk ids. The registry stays empty.
RISK_VALUES: frozenset[str] = frozenset()


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value!r}")


@dataclass(frozen=True)
class Tag:
    """One ``namespace:value`` custody tag."""

    namespace: Namespace
    value: str

    def text(self) -> str:
        return f"{self.namespace}:{self.value}"


def parse_tag(text: str, *, known_owners: frozenset[str] | None = None) -> Tag:
    """Parse one tag. An unknown namespace or an unregistered value fails closed.

    ``known_owners`` is the operator allow-list for ``owner:``. The default list
    is empty, so an owner tag fails closed until a later phase supplies names.
    """
    if not isinstance(text, str) or text != text.strip() or text.count(":") != 1:
        raise ValueError("tag must be namespace:value")
    namespace, value = text.split(":", 1)
    known = _namespace(namespace)
    if not value or value != value.strip() or not SCOPE_ID_RE.fullmatch(value):
        raise ValueError("tag value must match the safe id pattern")
    owners = known_owners if known_owners is not None else frozenset()
    match known:
        case "platform":
            if value not in PLATFORM_VALUES:
                raise ValueError("unknown platform tag")
        case "evidence":
            if value not in EVIDENCE_VALUES:
                raise ValueError("unknown evidence tag")
        case "owner":
            if value not in owners:
                raise ValueError("unknown owner tag")
        case "automation":
            if value not in AUTOMATION_VALUES:
                raise ValueError("unknown automation tag")
        case "framework":
            if not framework_id_on_pin(value):
                raise ValueError("unknown framework tag")
        case "control":
            if value not in SEEDED_CONTROL_IDS:
                raise ValueError("unknown control tag")
        case "risk":
            if value not in RISK_VALUES:
                raise ValueError("unknown risk tag")
        case _ as unknown:
            _never(unknown)
    return Tag(namespace=known, value=value)


def _namespace(value: str) -> Namespace:
    match value:
        case "platform" | "evidence" | "owner" | "automation" | "framework" | "control" | "risk":
            return value
        case _:
            raise ValueError("unknown tag namespace")
