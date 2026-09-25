"""Assessment surfaces preserve scope, refresh, and operator-review boundaries."""

from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient
from textual.widgets import Input, Select, Static

import beacon.gui.app as gui
import beacon.mcp.server as mcp
import beacon.tui.app as tui
from beacon.errors import BeaconError


SPEC_HASH = "a" * 64
RECEIPT_ID = "b" * 64


def example_row(*, current: bool = True):
    return {
        "receipt": {
            "spec_id": "encryption-v1",
            "spec_sha256": SPEC_HASH,
            "scope_id": "production",
            "status": "insufficient",
            "evaluated_at": "2026-09-25T18:00:00Z",
            "input_sha256": "c" * 64,
            "results": [{
                "criterion_id": "volume-coverage",
                "assertion": "Every production volume is observed",
                "status": "insufficient",
                "eligibility": {"eligible": False, "reasons": ["missing population"]},
                "evidence": [{"evidence_id": "volume-snapshot", "payload_sha256": "d" * 64}],
            }],
            "gaps": ["Two expected volumes are missing."],
            "findings": [],
            "objective_satisfied": False,
            "control_satisfied": False,
        },
        "evidence_id": RECEIPT_ID,
        "current": current,
        "invalidation_reasons": [] if current else ["Evidence changed since evaluation."],
        "review": None,
    }


def test_api_and_mcp_share_real_receipts_and_idempotent_refresh(initialized):
    from beacon.assurance.specs import draft_ebs_spec, import_spec
    from beacon.config import load_settings
    from beacon.scope.store import import_scope, new_scope_document
    from beacon.workspace import seed_workspace

    settings = load_settings()
    spec = import_spec(settings, json.dumps(draft_ebs_spec()))
    document = new_scope_document("production").canonical_body()
    document.update(schema_version=2, allowed_evidence_kinds=["cloud_inspector", "policy"],
                    boundary={"accounts": ["123456789012"], "regions": ["us-east-1"]},
                    parameters={"approved_assessment_sha256": [spec["spec_sha256"]]})
    import_scope(settings, json.dumps(document))
    seed_workspace(settings)
    client = TestClient(gui.create_app(), headers={"X-Beacon-Request": "1"})
    listed = client.get("/api/assessment-specs", params={"scope_id": "production"}).json()["specs"]
    assert len(listed) == 1 and listed[0]["approved"] is True
    response = client.post("/api/assess", json={"scope_id": "production", "spec_sha256": spec["spec_sha256"]})
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["status"] == "insufficient"
    assert receipt["gaps"]
    assert receipt["objective_satisfied"] is False
    assert receipt["control_satisfied"] is False
    via_mcp = mcp.call_tool("beacon_assessments", {"scope_id": "production"})["assessments"]
    via_web = client.get("/api/assessments", params={"scope_id": "production"}).json()["assessments"]
    assert via_mcp == via_web
    assert via_mcp[0]["evidence_id"] == receipt["receipt_evidence_id"]
    refreshed = mcp.call_tool("beacon_refresh_assessments", {"scope_id": "production"})
    assert refreshed["unchanged"] == 1
    assert refreshed["evaluations"] == []
    assert refreshed["collections"] == []


def test_api_assessment_writes_cannot_authorize_collection_or_review(initialized, monkeypatch):
    calls = []
    monkeypatch.setattr(gui, "refresh_assessments", lambda settings, **kwargs: calls.append(kwargs) or {"evaluations": [], "unchanged": 1, "collections": []})
    client = TestClient(gui.create_app(), headers={"X-Beacon-Request": "1"})
    response = client.post("/api/assessments/refresh", json={"scope_id": "production"})
    assert response.status_code == 200
    assert calls == [{"scope_id": "production", "collect_missing": False}]
    for extra in ({"collect_missing": True}, {"actor": "authorized-reviewer"}):
        assert client.post("/api/assessments/refresh", json={"scope_id": "production", **extra}).status_code == 422
    assert len(calls) == 1
    assert client.post("/api/assess", json={"scope_id": "production", "spec_sha256": SPEC_HASH, "decision": "accept"}).status_code == 422
    assert client.post("/api/assessments/review", json={"receipt_evidence_id": RECEIPT_ID, "decision": "accept", "rationale": "ok"}).status_code == 404


def test_api_assessment_errors_and_stale_reasons_are_visible(initialized, monkeypatch):
    row = example_row(current=False)
    monkeypatch.setattr(gui, "list_assessments", lambda settings, **kwargs: [row])
    monkeypatch.setattr(gui, "review_queue", lambda settings, **kwargs: [row])

    def reject(settings, **kwargs):
        raise BeaconError("E_SPEC_APPROVAL", "Specification hash is not approved for this scope")

    monkeypatch.setattr(gui, "evaluate_assessment", reject)
    client = TestClient(gui.create_app(), headers={"X-Beacon-Request": "1"})
    for endpoint in ("/api/assessments", "/api/review-queue"):
        result = client.get(endpoint, params={"scope_id": "production"}).json()["assessments"][0]
        assert result["current"] is False
        assert result["invalidation_reasons"] == ["Evidence changed since evaluation."]
        assert result["receipt"]["gaps"] == ["Two expected volumes are missing."]
    result = client.post("/api/assess", json={"scope_id": "production", "spec_sha256": SPEC_HASH})
    assert result.status_code == 400
    assert result.json()["code"] == "E_SPEC_APPROVAL"
    assert result.json()["ok"] is False


def test_mcp_assessment_tools_cannot_collect_or_impersonate_reviewers(initialized, monkeypatch):
    calls = []
    monkeypatch.setattr(mcp, "refresh_assessments", lambda settings, **kwargs: calls.append(kwargs) or {"evaluations": [], "unchanged": 1})
    result = mcp.call_tool("beacon_refresh_assessments", {"scope_id": "production"})
    assert result["unchanged"] == 1
    assert calls == [{"scope_id": "production", "collect_missing": False}]
    for extra in ({"collect_missing": True}, {"actor": "authorized-reviewer"}, {"decision": "accept"}):
        result = mcp.call_tool("beacon_refresh_assessments", {"scope_id": "production", **extra})
        assert result["code"] == "E_ARGUMENT"
    assert len(calls) == 1
    assert not any("review" in name and name != "beacon_review_queue" for name in mcp.TOOLS)
    assert "beacon_assess" in mcp.TOOLS
    assert "beacon_assessment_specs" in mcp.TOOLS


def test_tui_assessment_detail_preserves_missing_and_stale_evidence():
    row = example_row(current=False)
    row["receipt"]["gaps"].append("[bold green]injected success[/]")
    text = tui._assessment_text(row)
    assert "REEVALUATION REQUIRED" in text.plain
    assert "Two expected volumes are missing." in text.plain
    assert "missing population" in text.plain
    assert "volume-snapshot" in text.plain
    assert "[bold green]injected success[/]" in text.plain
    assert "Objective and control satisfaction remain unset." in text.plain
    assert "Checks passed" not in text.plain


@pytest.mark.asyncio
async def test_tui_assessment_scope_change_and_rationale_require_explicit_action(initialized, monkeypatch):
    row = example_row()
    reviews = []
    evaluations = []
    monkeypatch.setattr(tui, "list_specs", lambda settings, **kwargs: [{"spec": {"spec_id": "encryption-v1", "title": "Encryption coverage"}, "spec_sha256": SPEC_HASH, "approved": True}])
    monkeypatch.setattr(tui, "list_assessments", lambda settings, **kwargs: [row])
    monkeypatch.setattr(tui, "record_review", lambda settings, **kwargs: reviews.append(kwargs) or {})
    monkeypatch.setattr(tui, "evaluate_assessment", lambda settings, **kwargs: evaluations.append(kwargs) or row["receipt"])
    app = tui.BeaconTUI(skip_tour=True)
    async with app.run_test(size=(100, 35)) as pilot:
        app.query_one("#scope", Input).value = "production"
        app.action_assessments()
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, tui.AssessmentScreen)
        screen.query_one("#assessment-receipt", Select).value = RECEIPT_ID
        await pilot.pause()
        assert screen.query_one("#assessment-accept").disabled is True
        screen.on_button_pressed(tui.Button.Pressed(screen.query_one("#assessment-reject")))
        assert reviews == []
        assert "required review rationale" in str(screen.query_one("#assessment-notice", Static).render())
        screen.query_one("#assessment-rationale", Input).value = "Collection does not cover the approved inventory."
        screen.on_button_pressed(tui.Button.Pressed(screen.query_one("#assessment-reject")))
        assert reviews == [{"receipt_evidence_id": RECEIPT_ID, "decision": "reject", "rationale": "Collection does not cover the approved inventory."}]
        screen.query_one("#assessment-scope", Input).value = "different-scope"
        screen.on_button_pressed(tui.Button.Pressed(screen.query_one("#assessment-run")))
        assert evaluations == []
        assert "Scope changed" in str(screen.query_one("#assessment-notice", Static).render())
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, tui.AssessmentScreen)


@pytest.mark.asyncio
async def test_tui_no_approved_specification_does_not_offer_pass(initialized, monkeypatch):
    monkeypatch.setattr(tui, "list_specs", lambda settings, **kwargs: [])
    monkeypatch.setattr(tui, "list_assessments", lambda settings, **kwargs: [])
    app = tui.BeaconTUI(skip_tour=True)
    async with app.run_test(size=(80, 24)) as pilot:
        app.query_one("#scope", Input).value = "production"
        app.action_assessments()
        await pilot.pause()
        screen = app.screen
        assert screen.query_one("#assessment-run").disabled is True
        assert screen.query_one("#assessment-accept").disabled is True
        assert "No approved specification" in str(screen.query_one("#assessment-spec-note", Static).render())
