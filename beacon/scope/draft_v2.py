"""Draft scope schema version 2. ``beacon scope init`` still writes version 1.

This module does not write ``.beacon/scopes/``. A later phase may write drafts
under ``.beacon/scopes/drafts/``. Agents may build this object. They must not commit it.
"""

from __future__ import annotations

from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from beacon.assurance.pin_ids import framework_id_on_pin
from beacon.assurance.tags import Tag, parse_tag
from beacon.canonical import sha256_obj
from beacon.scope.document import SCOPE_ID_RE, ScopeDocument

DRAFT_SCHEMA_VERSION = 2
ComponentKind = Literal["component", "service"]
ComponentStatus = Literal["proposed", "in_scope", "excluded"]


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value!r}")


def _safe_id(value: str, *, label: str) -> str:
    if not SCOPE_ID_RE.fullmatch(value):
        raise ValueError(f"{label} must match the safe id pattern")
    return value


class ComponentService(BaseModel):
    """One component or service in the workshop. Status is a workshop state, not a claim."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ComponentKind
    id: str
    role: str = Field(min_length=1)
    platform: str
    context: str = Field(min_length=1)
    solutions_refs: tuple[str, ...] = ()
    risk_refs: tuple[str, ...] = ()
    status: ComponentStatus = "proposed"
    tags: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def check_id(cls, value: str) -> str:
        return _safe_id(value, label="component id")

    @field_validator("role", "context")
    @classmethod
    def text_is_trimmed(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("text must not have surrounding space")
        return value

    @field_validator("platform")
    @classmethod
    def platform_is_registered(cls, value: str) -> str:
        parse_tag(f"platform:{value}")
        return value

    @field_validator("solutions_refs", "risk_refs")
    @classmethod
    def refs_are_safe(cls, values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values:
            text = _safe_id(item, label="ref")
            if text in seen:
                raise ValueError("refs must not repeat")
            seen.add(text)
            cleaned.append(text)
        return tuple(cleaned)

    @model_validator(mode="after")
    def tags_parse(self) -> ComponentService:
        parsed = _parse_tags(self.tags)
        platform_tags = [tag.value for tag in parsed if tag.namespace == "platform"]
        if len(platform_tags) > 1:
            raise ValueError("component has more than one platform tag")
        if platform_tags and platform_tags[0] != self.platform:
            raise ValueError("platform tag must match the component platform")
        return self


class FrameworkContext(BaseModel):
    """One selected framework. The crosswalk is a lens. This object does not blend frameworks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework_id: str
    required_components: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @field_validator("framework_id")
    @classmethod
    def framework_is_on_pin(cls, value: str) -> str:
        if not framework_id_on_pin(value):
            raise ValueError("framework_id is not on the catalog pin")
        return value

    @field_validator("required_components", "rules")
    @classmethod
    def labels_are_safe(cls, values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values:
            text = _safe_id(item, label="framework label")
            if text in seen:
                raise ValueError("framework labels must not repeat")
            seen.add(text)
            cleaned.append(text)
        return tuple(cleaned)

    @model_validator(mode="after")
    def tags_parse_and_match_framework(self) -> FrameworkContext:
        parsed = _parse_tags(self.tags)
        for tag in parsed:
            match tag.namespace:
                case "framework":
                    if tag.value != self.framework_id:
                        raise ValueError("framework tag must name this framework context")
                case "platform" | "evidence" | "owner" | "automation" | "control" | "risk":
                    pass
                case _ as unknown:
                    _never(unknown)
        return self


class ScopeDraftV2(BaseModel):
    """Workshop draft. ``scope`` is a version 1 document. Extra fields live only here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[2] = DRAFT_SCHEMA_VERSION
    scope: ScopeDocument
    components: tuple[ComponentService, ...] = ()
    tags: tuple[str, ...] = ()
    framework_context: tuple[FrameworkContext, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def bind_context_to_scope(self) -> ScopeDraftV2:
        _parse_tags(self.tags)
        seen: set[str] = set()
        component_ids = {item.id for item in self.components}
        for item in self.components:
            if item.id in seen:
                raise ValueError("component ids must not repeat")
            seen.add(item.id)
        context_ids: list[str] = []
        for item in self.framework_context:
            if item.framework_id in context_ids:
                raise ValueError("framework context ids must not repeat")
            context_ids.append(item.framework_id)
            if item.framework_id not in self.scope.frameworks:
                raise ValueError("framework context must name a framework on the scope document")
            for component_id in item.required_components:
                if component_id not in component_ids:
                    raise ValueError("required component is not on the draft")
        for framework_id in self.scope.frameworks:
            if not framework_id_on_pin(framework_id):
                raise ValueError("scope framework id is not on the catalog pin")
        return self

    def canonical_body(self) -> dict:
        return self.model_dump(mode="json")

    def content_sha256(self) -> str:
        return sha256_obj(self.canonical_body())


def _parse_tags(values: tuple[str, ...]) -> tuple[Tag, ...]:
    parsed: list[Tag] = []
    seen: set[str] = set()
    for item in values:
        tag = parse_tag(item)
        if tag.text() in seen:
            raise ValueError("tags must not repeat")
        seen.add(tag.text())
        parsed.append(tag)
    return tuple(parsed)
