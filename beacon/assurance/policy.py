"""Git policy objects addressed by path and content hash.

The JSON file is the source of truth. Word and PDF files are refused.
This module does not seal a witness record and does not assert a control.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from beacon.assurance.pin_ids import SEEDED_CONTROL_IDS
from beacon.canonical import sha256_bytes, sha256_obj
from beacon.crypto.witness import CHAIN_VERSION
from beacon.errors import E_POLICY, fail
from beacon.scope.document import SCOPE_ID_RE, SHA256_RE

SCHEMA_VERSION = 1
POLICY_TAG = "evidence:policy"
OFFICE_SUFFIXES = frozenset({".pdf", ".doc", ".docx", ".docm", ".rtf", ".odt"})


def _policy_fail(message: str) -> None:
    fail(E_POLICY, message)


class Party(BaseModel):
    """A person or role named by the policy. The row is custody data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str
    name: str

    @field_validator("role", "name")
    @classmethod
    def text_is_present(cls, value: str) -> str:
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError("people text must be non-blank")
        return value


class ProcessStep(BaseModel):
    """One process step. The summary is operator text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    summary: str

    @field_validator("id")
    @classmethod
    def id_is_safe(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("process id must match the safe id pattern")
        return value

    @field_validator("summary")
    @classmethod
    def summary_is_present(cls, value: str) -> str:
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError("process summary must be non-blank")
        return value


class TechnologyRef(BaseModel):
    """One system the policy names. The row is not a collector result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    system: str

    @field_validator("id")
    @classmethod
    def id_is_safe(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("technology id must match the safe id pattern")
        return value

    @field_validator("system")
    @classmethod
    def system_is_present(cls, value: str) -> str:
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError("technology system must be non-blank")
        return value


class PolicyObject(BaseModel):
    """People, process, and technology for one git policy file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = SCHEMA_VERSION
    policy_id: str
    title: str
    people: tuple[Party, ...] = ()
    process: tuple[ProcessStep, ...] = ()
    technology: tuple[TechnologyRef, ...] = ()
    control_refs: tuple[str, ...] = ()
    scope_refs: tuple[str, ...] = ()

    @field_validator("policy_id")
    @classmethod
    def policy_id_is_safe(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("policy_id must match the safe id pattern")
        return value

    @field_validator("title")
    @classmethod
    def title_is_present(cls, value: str) -> str:
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError("title must be non-blank")
        return value

    @field_validator("control_refs")
    @classmethod
    def controls_are_seeded(cls, values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values:
            if item not in SEEDED_CONTROL_IDS:
                raise ValueError("control_refs accepts only the seeded control ids")
            if item in seen:
                raise ValueError("control_refs must not repeat")
            seen.add(item)
            cleaned.append(item)
        return tuple(cleaned)

    @field_validator("scope_refs")
    @classmethod
    def scopes_are_safe(cls, values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values:
            if not SCOPE_ID_RE.fullmatch(item):
                raise ValueError("scope_refs must match the safe id pattern")
            if item in seen:
                raise ValueError("scope_refs must not repeat")
            seen.add(item)
            cleaned.append(item)
        return tuple(cleaned)

    def canonical_body(self) -> dict:
        return self.model_dump(mode="json")

    def content_sha256(self) -> str:
        return sha256_obj(self.canonical_body())


class PolicyCustody(BaseModel):
    """Path and hashes for one policy file. The tag is custody metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    content_sha256: str
    file_sha256: str
    tag: Literal["evidence:policy"] = POLICY_TAG
    role: Literal["candidate"] = "candidate"
    source_of_truth: Literal["git"] = "git"
    git_sha: str | None = None
    record_v: Literal[1] = CHAIN_VERSION
    policy_id: str

    @field_validator("content_sha256", "file_sha256")
    @classmethod
    def hash_is_sha256(cls, value: str) -> str:
        if not SHA256_RE.fullmatch(value):
            raise ValueError("hash must be 64 lowercase hex characters")
        return value

    @field_validator("git_sha")
    @classmethod
    def git_sha_is_hex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) not in (40, 64) or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("git_sha must be 40 or 64 lowercase hex characters")
        return value


def read_git_head(root: Path) -> str | None:
    """Return HEAD when git can read it. A missing repository returns None."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip().lower()
    if len(sha) not in (40, 64) or any(char not in "0123456789abcdef" for char in sha):
        return None
    return sha


def resolve_policy_path(root: Path, relative: str) -> Path:
    """Resolve one relative policy path. Office files and path escape fail closed."""
    if not isinstance(relative, str) or not relative or relative != relative.strip():
        _policy_fail("policy path must be a non-blank relative path")
    if relative.startswith(("/", "\\")) or "\\" in relative:
        _policy_fail("policy path must be relative")
    suffix = Path(relative).suffix.lower()
    if suffix in OFFICE_SUFFIXES:
        _policy_fail("Word and PDF files are not the policy source of truth")
    if suffix != ".json":
        _policy_fail("policy source of truth must be a JSON file")
    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _policy_fail("policy path must stay under the policy root")
    root_resolved = root.resolve()
    path = (root_resolved / relative).resolve()
    if path != root_resolved and root_resolved not in path.parents:
        _policy_fail("policy path must stay under the policy root")
    return path


def load_policy_file(root: Path, relative: str) -> tuple[Path, PolicyObject, str]:
    """Read one policy file and return the path, object, and raw-byte hash."""
    path = resolve_policy_path(root, relative)
    if not path.is_file():
        _policy_fail("policy file is missing")
    raw = path.read_bytes()
    try:
        document = PolicyObject.model_validate_json(raw)
    except ValidationError as exc:
        _policy_fail(f"policy file failed validation: {exc.errors()[0]['msg']}")
    return path, document, sha256_bytes(raw)


def address_policy(
    root: Path,
    relative: str,
    *,
    expect_sha256: str | None = None,
    git_sha: str | None = None,
) -> tuple[PolicyObject, PolicyCustody]:
    """Address one policy by path and canonical content hash."""
    path, document, file_sha256 = load_policy_file(root, relative)
    content_sha256 = document.content_sha256()
    if expect_sha256 is not None:
        if not SHA256_RE.fullmatch(expect_sha256):
            _policy_fail("expect-sha256 must be 64 lowercase hex characters")
        if expect_sha256 != content_sha256:
            _policy_fail("policy content hash does not match")
    head = git_sha if git_sha is not None else read_git_head(root)
    try:
        relative_posix = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        _policy_fail("policy path must stay under the policy root")
    custody = PolicyCustody(
        path=relative_posix,
        content_sha256=content_sha256,
        file_sha256=file_sha256,
        git_sha=head,
        policy_id=document.policy_id,
        record_v=CHAIN_VERSION,
    )
    if custody.record_v != 1:
        _policy_fail("record version must stay 1")
    return document, custody
