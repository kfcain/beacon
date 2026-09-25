"""GUI pages and TUI screens."""

from __future__ import annotations

from fastapi.testclient import TestClient

from beacon.gui.app import create_app
from beacon.tui.app import SCREENS
from beacon.workspace import seed_workspace
from beacon.config import load_settings


def test_tui_screens_include_collect():
    assert SCREENS == ("dashboard", "freshness", "validation", "push", "system", "collect")


def test_gui_pages(initialized):
    seed_workspace(load_settings())
    client = TestClient(create_app(), headers={"X-Beacon-Request":"1"})
    home = client.get("/")
    assert home.status_code == 200
    html = home.text
    for label in ("Dashboard", "Freshness", "Validation", "Push", "System"):
        assert label in html
    dash = client.get("/api/dashboard")
    assert dash.status_code == 200
    pages = dash.json()["pages"]
    assert pages == ["dashboard", "assessment", "freshness", "validation", "push", "system"]
    fresh = client.get("/api/freshness")
    assert fresh.status_code == 200
    valid = client.get("/api/validation")
    assert valid.status_code == 200
    assert valid.json()["ok"] is True
    system = client.get("/api/system")
    assert system.status_code == 200
    assert system.json()["keys_distinct"] is True
    pushed = client.post("/api/push")
    assert pushed.status_code == 200
    assert pushed.json()["ok"] is True
