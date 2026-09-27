"""TUI walkthrough steps, first-run flag, and skip behavior."""

from __future__ import annotations

import pytest

from beacon.config import load_settings
from beacon.tui.app import SCREENS, BeaconTUI, TourScreen
from beacon.tui.tour import (
    TOUR_STEPS,
    TourCursor,
    is_tour_seen,
    mark_tour_seen,
    should_auto_start_tour,
    skip_tour_requested,
    tour_seen_path,
)

_FORBIDDEN = ("compliant", "evidenced", "proven")
_OLD_SEED_IDS = ("IAC-01", "CRY-05", "GOV-01")


def _tour_text() -> str:
    return "\n".join(f"{step.title}\n{step.body}" for step in TOUR_STEPS)


def test_tour_steps_cover_the_workflow():
    ids = [step.id for step in TOUR_STEPS]
    assert ids == [
        "what",
        "dashboard",
        "collect",
        "validation",
        "freshness",
        "push",
        "lake",
        "system",
    ]
    focuses = [step.focus for step in TOUR_STEPS]
    for focus in focuses:
        assert focus in SCREENS
    text = _tour_text()
    assert "evidence engine" in text
    assert 'not "control met"' in text
    assert "IAC-02" in text
    assert "CRY-07" in text
    assert "Identity & Access Management" in text
    assert "Encrypting Data At Rest" in text
    assert "E_NO_CHECKPOINT" in text
    assert "beacon check" in text
    assert "public keys" in text
    assert "Private keys" in text
    assert "BEACON_S3_BUCKET" in text
    assert "keys_distinct" in text
    assert "2026.3" in text
    lowered = text.lower()
    for word in _FORBIDDEN:
        assert word not in lowered
    for old_id in _OLD_SEED_IDS:
        assert old_id not in text


def test_tour_cursor_next_and_back_stay_in_range():
    cursor = TourCursor()
    assert cursor.at_start
    assert cursor.step.id == "what"
    cursor.back()
    assert cursor.index == 0
    seen = [cursor.step.id]
    while not cursor.at_end:
        cursor.next()
        seen.append(cursor.step.id)
    assert seen == [step.id for step in TOUR_STEPS]
    cursor.next()
    assert cursor.at_end
    assert cursor.step.focus == "system"
    cursor.restart()
    assert cursor.step.id == "what"


def test_tour_seen_flag(beacon_home):
    home = beacon_home
    assert should_auto_start_tour(home, skip=False) is True
    assert should_auto_start_tour(home, skip=True) is False
    path = mark_tour_seen(home)
    assert path == tour_seen_path(home)
    assert path.is_file()
    assert is_tour_seen(home) is True
    assert should_auto_start_tour(home, skip=False) is False


def test_skip_tour_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("BEACON_NO_TOUR", raising=False)
    assert skip_tour_requested(False) is False
    assert skip_tour_requested(True) is True
    monkeypatch.setenv("BEACON_NO_TOUR", "1")
    assert skip_tour_requested(False) is True
    monkeypatch.setenv("BEACON_NO_TOUR", "no")
    assert skip_tour_requested(False) is False


@pytest.mark.asyncio
async def test_tui_auto_starts_tour_and_records_seen(beacon_home):
    app = BeaconTUI()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, TourScreen)
        assert app.current == "dashboard"
        await pilot.press("right")
        await pilot.pause()
        assert app.current == "dashboard"
        assert app.screen.cursor.step.id == "dashboard"
        await pilot.press("right")
        await pilot.pause()
        assert app.current == "collect"
        assert "IAC-02" in app.screen.cursor.step.body
        await pilot.press("left")
        await pilot.pause()
        assert app.current == "dashboard"
        await pilot.press("escape")
        await pilot.pause()
    assert is_tour_seen(load_settings().home)
    again = BeaconTUI()
    async with again.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert not isinstance(again.screen, TourScreen)
        assert again.current == "dashboard"


@pytest.mark.asyncio
async def test_tui_skip_flag_and_rerun_key(beacon_home):
    app = BeaconTUI(skip_tour=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert not isinstance(app.screen, TourScreen)
        await pilot.press("question_mark")
        await pilot.pause()
        assert isinstance(app.screen, TourScreen)
        assert app.screen.cursor.step.id == "what"
        hit = await pilot.click("#tour-done", offset=(2, 1))
        assert hit is True
        await pilot.pause()
        assert not isinstance(app.screen, TourScreen)
    assert is_tour_seen(beacon_home)
    replay = BeaconTUI()
    async with replay.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert not isinstance(replay.screen, TourScreen)
        hit = await pilot.click("#do-tour", offset=(2, 1))
        assert hit is True
        await pilot.pause()
        assert isinstance(replay.screen, TourScreen)
        await pilot.press("right")
        await pilot.pause()
        assert replay.screen.cursor.index == 1
        await pilot.press("h")
        await pilot.pause()
        assert replay.screen.cursor.index == 0
        assert replay.current == "dashboard"


@pytest.mark.asyncio
async def test_target_field_keeps_the_letter_h(beacon_home):
    app = BeaconTUI(skip_tour=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.click("#target", offset=(2, 1))
        await pilot.press("h")
        await pilot.pause()
        assert app.query_one("#target").value == "h"
        assert not isinstance(app.screen, TourScreen)
        await pilot.press("question_mark")
        await pilot.pause()
        assert isinstance(app.screen, TourScreen)
        assert app.query_one("#target").value == "h"
        screen = app.screen
        for _ in range(screen.cursor.total):
            body = screen.query_one("#tour-body")
            scroll = screen.query_one("#tour-scroll")
            assert body.size.height <= scroll.size.height
            assert "control met" in screen.cursor.step.body or screen.cursor.step.id not in {
                "what",
                "collect",
                "validation",
                "lake",
            }
            if not screen.cursor.at_end:
                await pilot.press("right")
                await pilot.pause()
        await pilot.press("q")
        await pilot.pause()
        assert not app.is_running


@pytest.mark.asyncio
async def test_tui_live_collection_is_explicit_and_reports_mode(initialized, monkeypatch):
    calls = []

    def fake_collect_named(settings, name, ctx, **kwargs):
        calls.append(ctx.live)
        return {"plugin": name, "mode": "live" if ctx.live else "fixture", "ok": True}

    monkeypatch.setattr("beacon.tui.app.collect_named", fake_collect_named)
    app = BeaconTUI(skip_tour=True)
    messages = []
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        monkeypatch.setattr(app, "notify", lambda message, **kwargs: messages.append(message))
        app.query_one("#plugin").value = "aws.ebs.encryption"
        assert app.query_one("#live").value is False
        app._collect()
        app.query_one("#live").value = True
        app._collect()
    assert calls == [False, True]
    assert messages == ["collected aws.ebs.encryption=fixture", "collected aws.ebs.encryption=live"]
