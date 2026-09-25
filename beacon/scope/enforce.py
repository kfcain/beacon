"""Boundary predicates shared by collectors and evidence admission."""
from __future__ import annotations

from beacon.errors import fail
from beacon.scf.catalog_pin import PINNED_SCF_VERSION


def evidence_kind(plugin: str) -> str:
    if plugin == "git.policy":
        return "policy"
    if plugin in {"aws.inspector", "azure.inspector", "gcp.inspector", "aws.ebs.encryption"}:
        return "cloud_inspector"
    if plugin == "aws.lake.logs":
        return "lake_log_extract"
    if plugin == "scf.catalog.offline":
        return "catalog_pin"
    return "drop_in"


def excluded_frameworks(document) -> set[str]:
    return {item.value for item in document.exclusions if item.kind == "framework"}


def reject_framework_conflict(document) -> None:
    if excluded_frameworks(document) & set(document.frameworks):
        fail("E_SCOPE", "scope both names and excludes the same framework")


def validate_plugin_scope(document, plugin: str) -> None:
    from beacon.assurance.pin_ids import framework_id_on_pin
    kind = evidence_kind(plugin)
    if document.catalog_pin_version != PINNED_SCF_VERSION:
        fail("E_SCOPE", "scope catalog version differs from the pinned catalog")
    if any(not framework_id_on_pin(item) for item in document.frameworks):
        fail("E_SCOPE", "scope names a framework outside the pinned catalog")
    reject_framework_conflict(document)
    if kind not in document.allowed_evidence_kinds:
        fail("E_SCOPE", f"scope does not allow evidence kind {kind}")
    if any(item.kind == "evidence_kind" and item.value == kind for item in document.exclusions):
        fail("E_SCOPE", "evidence kind is excluded")


def boundary_reasons(document, payload: dict) -> list[str]:
    """A live observation must supply actual source identity and collection regions."""
    identity = payload.get("identity")
    if not isinstance(identity, dict):
        return ["source_identity_missing"]
    actual = {
        "account": identity.get("account_id"),
        "subscription": identity.get("subscription_id"),
        "project": identity.get("project_id"),
        "system": identity.get("system_id"),
    }
    reasons = []
    boundary = document.boundary
    for kind, field in (("account", "accounts"), ("subscription", "subscriptions"),
                        ("project", "projects"), ("system", "systems")):
        if payload.get("source") == "git.policy" and kind != "system":
            continue
        allowed = getattr(boundary, field)
        # The default local workspace label is not a cloud account boundary.
        if kind == "system" and tuple(allowed) == ("workspace",):
            continue
        if allowed and actual[kind] not in allowed:
            reasons.append(f"{kind}_out_of_boundary")
    cloud = payload.get("cloud")
    if cloud == "aws":
        arn = identity.get("arn", "").split(":") if isinstance(identity.get("arn", ""), str) else []
        if len(arn) < 6 or arn[0] != "arn" or arn[4] != actual["account"] or arn[1] != identity.get("partition"):
            reasons.append("principal_identity_mismatch")
    required = {"aws": "account", "azure": "subscription", "gcp": "project"}.get(cloud)
    if required and not actual[required]:
        reasons.append("source_identity_missing")
    if cloud == "aws" and not boundary.accounts:
        reasons.append("account_boundary_missing")
    if cloud == "azure" and not boundary.subscriptions:
        reasons.append("subscription_boundary_missing")
    if cloud == "gcp" and not boundary.projects:
        reasons.append("project_boundary_missing")
    regions = payload.get("regions")
    if cloud in {"aws", "azure", "gcp"}:
        if not boundary.regions or not isinstance(regions, list) or not regions:
            reasons.append("region_boundary_missing")
        elif any(not isinstance(region, str) or region not in boundary.regions for region in regions):
            reasons.append("region_out_of_boundary")
    tags = payload.get("tags")
    tagged_frameworks = {tag.split(":", 1)[1] for tag in tags if isinstance(tag, str) and tag.startswith("framework:")} \
        if isinstance(tags, list) else set()
    for exclusion in document.exclusions:
        if exclusion.kind in actual and actual[exclusion.kind] == exclusion.value:
            reasons.append(f"excluded_{exclusion.kind}")
        elif exclusion.kind == "region" and isinstance(regions, list) and exclusion.value in regions:
            reasons.append("excluded_region")
        elif exclusion.kind == "framework" and exclusion.value in tagged_frameworks:
            reasons.append("excluded_framework")
    return sorted(set(reasons))
