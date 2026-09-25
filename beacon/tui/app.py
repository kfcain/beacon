"""Paramify-style TUI: Dashboard, Freshness, Validation, Push, System, Collect."""

from __future__ import annotations

from typing import Any, Literal, assert_never

import json
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Footer, Header, Input, Static

from beacon.config import load_settings
from beacon.errors import BeaconError
from beacon.plugins.spec import CollectContext
from beacon.push import write_pack
from beacon.scf.engine import collect_all, collect_target, collect_named
from beacon.assurance.evaluation import evaluate_control
from beacon.tui.theme import BEACON_DARK, BLUE_TEXT, FAIL, MUTED, OK
from beacon.tui.tour import (
    TourCursor,
    mark_tour_seen,
    should_auto_start_tour,
    skip_tour_requested,
)
from beacon.workspace import freshness, system_status, validation

ScreenName = Literal["dashboard", "freshness", "validation", "push", "system", "collect"]
SCREENS: tuple[ScreenName, ...] = (
    "dashboard",
    "freshness",
    "validation",
    "push",
    "system",
    "collect",
)

def _status_line() -> Text:
    data = validation(load_settings())
    text = Text()
    text.append("Beacon  ", style=f"bold {BLUE_TEXT}")
    if data.get("ok"):
        text.append("VALIDATION OK", style=f"bold {OK}")
    else:
        text.append(str(data.get("code") or "FAIL"), style=f"bold {FAIL}")
        if data.get("message"):
            text.append(f"  {data['message']}", style=MUTED)
    return text


def _kv(label: str, value: Any) -> str:
    return f"[bold {BLUE_TEXT}]{label}[/]\n{value}\n"


class Pane(Static):
    DEFAULT_CSS = "Pane { width: 1fr; height: 1fr; padding: 1 2; background: $surface; }"


class TargetInput(Input):
    """SCF target field. `?` stays a tour binding."""

    def check_consume_key(self, key: str, character: str | None) -> bool:
        if key == "question_mark":
            return False
        return super().check_consume_key(key, character)


class TourScreen(ModalScreen[None]):
    """Next / Back / Skip / Done walkthrough. Points at the live tab behind it."""

    DEFAULT_CSS = """
    TourScreen { align: center middle; background: $background 80%; }
    #tour-dialog {
        width: 68;
        height: auto;
        max-height: 18;
        background: $surface;
        border: tall $primary;
        padding: 1 2;
    }
    #tour-kicker { color: $primary-lighten-2; text-style: bold; }
    #tour-title { color: $primary-lighten-2; text-style: bold; }
    #tour-step { color: $text-muted; }
    #tour-scroll {
        height: 6;
        margin: 1 0 0 0;
        background: $surface;
    }
    #tour-body { color: $foreground; height: auto; }
    #tour-actions { height: 3; margin-top: 1; }
    #tour-actions Button {
        margin: 0 1 0 0;
        min-width: 0;
        width: auto;
        padding: 0 1;
    }
    """
    BINDINGS = [
        Binding("escape", "skip_tour", "Skip", show=False),
        Binding("left", "tour_back", "Back", show=False),
        Binding("right", "tour_next", "Next", show=False),
        Binding("h", "restart_tour", "Tour", show=False),
        Binding("question_mark", "restart_tour", "Tour", show=False),
        Binding("q", "quit", "Quit", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.cursor = TourCursor()

    def compose(self) -> ComposeResult:
        with Vertical(id="tour-dialog"):
            yield Static("Walkthrough", id="tour-kicker")
            yield Static("", id="tour-title")
            yield Static("", id="tour-step")
            with VerticalScroll(id="tour-scroll"):
                yield Static("", id="tour-body")
            with Horizontal(id="tour-actions"):
                yield Button("Back", id="tour-back")
                yield Button("Next", id="tour-next", variant="primary")
                yield Button("Skip", id="tour-skip")
                yield Button("Done", id="tour-done")

    def on_mount(self) -> None:
        self.render_step()

    def render_step(self) -> None:
        step = self.cursor.step
        self.query_one("#tour-title", Static).update(step.title)
        self.query_one("#tour-step", Static).update(
            f"Step {self.cursor.index + 1} of {self.cursor.total}"
        )
        self.query_one("#tour-body", Static).update(step.body)
        self.query_one("#tour-back", Button).disabled = self.cursor.at_start
        app = self.app
        if isinstance(app, BeaconTUI):
            app.show_for_tour(step.focus)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "tour-back":
            event.stop()
            self.cursor.back()
            self.render_step()
            return
        if bid == "tour-next":
            event.stop()
            self.action_tour_next()
            return
        if bid in {"tour-skip", "tour-done"}:
            event.stop()
            self._finish()

    def action_tour_back(self) -> None:
        self.cursor.back()
        self.render_step()

    def action_tour_next(self) -> None:
        if self.cursor.at_end:
            self._finish()
            return
        self.cursor.next()
        self.render_step()

    def action_skip_tour(self) -> None:
        self._finish()

    def action_restart_tour(self) -> None:
        self.cursor.restart()
        self.render_step()

    def action_quit(self) -> None:
        self.app.exit()

    def _finish(self) -> None:
        app = self.app
        if isinstance(app, BeaconTUI):
            mark_tour_seen(load_settings().home)
        self.dismiss()


class BeaconTUI(App[None]):
    """Keyboard-first evidence console."""

    TITLE = "Beacon"
    CSS = """
    Screen { background: $background; color: $foreground; }
    Header, Footer { background: $panel; }
    Button:focus { border: tall $primary; }
    Input:focus { border: tall $primary; }
    #tabs { height: 3; dock: top; }
    #actions, #scope-actions { height: 3; }
    #scope, #plugin { width: 1fr; }
    #tabs Button, #actions Button {
        margin: 0 0 0 1;
        min-width: 0;
        width: auto;
        padding: 0 1;
    }
    #body { height: 1fr; }
    #target { width: 1fr; margin: 0 1; }
    """
    BINDINGS = [
        ("1", "show('dashboard')", "Dashboard"),
        ("2", "show('freshness')", "Freshness"),
        ("3", "show('validation')", "Validation"),
        ("4", "show('push')", "Push"),
        ("5", "show('system')", "System"),
        ("6", "show('collect')", "Collect"),
        Binding("question_mark", "tour", "Tour", priority=True),
        Binding("h", "tour", "Tour", show=False),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, *, skip_tour: bool = False) -> None:
        super().__init__()
        self.register_theme(BEACON_DARK)
        self.theme = BEACON_DARK.name
        self.current: ScreenName = "dashboard"
        self.skip_tour = skip_tour

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="tabs"):
            yield Button("Dashboard", id="tab-dashboard")
            yield Button("Freshness", id="tab-freshness")
            yield Button("Validation", id="tab-validation")
            yield Button("Push", id="tab-push")
            yield Button("System", id="tab-system")
            yield Button("Collect", id="tab-collect")
            yield Button("Tour", id="do-tour")
        with VerticalScroll(id="body"):
            yield Pane(id="pane")
        with Horizontal(id="scope-actions"):
            yield Input(placeholder="Enrolled scope id", id="scope")
            yield Input(placeholder="Plugin (optional, e.g. aws.ebs.encryption)", id="plugin")
            # Explicit opt-in, as in the web console and MCP. Off means fixture evidence.
            yield Checkbox("Live", id="live")
            yield Button("Evaluate target", id="do-evaluate")
        with Horizontal(id="actions"):
            yield TargetInput(
                placeholder="SCF target (IAC-02 / CRY-07) or empty for all",
                id="target",
            )
            yield Button("Collect", id="do-collect", variant="primary")
            yield Button("Push pack", id="do-push")
            yield Button("Recheck", id="do-check")
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_pane()
        if should_auto_start_tour(load_settings().home, skip=self.skip_tour):
            self.call_after_refresh(self.start_tour)

    def action_show(self, name: str) -> None:
        if name not in SCREENS:
            return
        self.current = name  # type: ignore[assignment]
        self.refresh_pane()

    def action_tour(self) -> None:
        self.start_tour()

    def start_tour(self) -> None:
        if isinstance(self.screen, TourScreen):
            self.screen.cursor.restart()
            self.screen.render_step()
            return
        self.push_screen(TourScreen())

    def show_for_tour(self, name: str) -> None:
        if name not in SCREENS:
            return
        self.current = name  # type: ignore[assignment]
        self.refresh_pane()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid.startswith("tab-"):
            name = bid.removeprefix("tab-")
            if name in SCREENS:
                self.current = name  # type: ignore[assignment]
            self.refresh_pane()
            return
        if bid == "do-evaluate":
            scope_id = self.query_one("#scope", Input).value.strip()
            target = self.query_one("#target", Input).value.strip().upper()
            try:
                result = evaluate_control(load_settings(), scope_id=scope_id, control_ref=target)
                self.query_one("#pane", Pane).update(Text(json.dumps(result, indent=2)))
            except BeaconError as exc:
                self.notify(str(exc), severity="error")
            return
        if bid == "do-collect":
            self._collect()
            return
        if bid == "do-push":
            self._push()
            return
        if bid == "do-check":
            self.current = "validation"
            self.refresh_pane()
            return
        if bid == "do-tour":
            self.start_tour()

    def refresh_pane(self) -> None:
        pane = self.query_one("#pane", Pane)
        settings = load_settings()
        current = self.current
        for name in SCREENS:
            self.query_one(f"#tab-{name}", Button).variant = (
                "primary" if name == current else "default"
            )
        match current:
            case "dashboard":
                pane.update(self._dashboard(settings))
            case "freshness":
                pane.update(self._freshness())
            case "validation":
                pane.update(self._validation())
            case "push":
                pane.update(f"[bold {BLUE_TEXT}]Push[/]\nExport a sealed pack with public keys only.\nPress Push pack.")
            case "system":
                pane.update(self._system(settings))
            case "collect":
                pane.update(
                    f"[bold {BLUE_TEXT}]Collect[/]\n"
                    "Enter an SCF id (IAC-02, CRY-07) or leave empty to run every overlapping fetcher.\n"
                    "Results are sealed on the witness chain. A Merkle/TSA checkpoint is written."
                )
            case _:
                assert_never(current)
        self.sub_title = str(_status_line())

    def _dashboard(self, settings) -> str:
        status = system_status(settings)
        chain = status.get("chain") or {}
        plugins = "\n".join(
            f"  • {p['name']}  ({', '.join(p.get('scf_targets') or [])})"
            for p in status.get("plugins") or []
        )
        return (
            f"[bold {BLUE_TEXT}]Dashboard[/]\n"
            f"records={status.get('records')}  checkpoints={status.get('checkpoints')}  "
            f"covered={chain.get('covered_through')}\n"
            f"SCF {status.get('scf_version')}  offline={status.get('scf_offline')}\n"
            "Press ? for the walkthrough.\n\n"
            f"[bold {BLUE_TEXT}]Plugins[/]\n{plugins or '  (none)'}"
        )

    def _freshness(self) -> str:
        rows = freshness(load_settings())
        if not rows:
            return f"[bold {BLUE_TEXT}]Freshness[/]\nNo sealed evidence. Run seed or collect."
        lines = [f"[bold {BLUE_TEXT}]Freshness[/]"]
        for item in rows:
            lines.append(f"  {item['plugin']:18}  {item['mode']:12}  seq={item['seq']}  {item['ts']}")
        return "\n".join(lines)

    def _validation(self) -> str:
        data = validation(load_settings())
        mark = "OK" if data.get("ok") else str(data.get("code"))
        return f"[bold {BLUE_TEXT}]Validation[/]\n{mark}\n{data}"

    def _system(self, settings) -> str:
        status = system_status(settings)
        return (
            f"[bold {BLUE_TEXT}]System[/]\n"
            + _kv("home", status.get("home"))
            + _kv("recorder", status.get("recorder_fingerprint"))
            + _kv("witness", status.get("witness_fingerprint"))
            + _kv("keys_distinct", status.get("keys_distinct"))
            + _kv("scf_api_base", status.get("scf_api_base"))
        )

    def _collect(self) -> None:
        target = self.query_one("#target", Input).value.strip() or None
        settings = load_settings()
        ctx = CollectContext(target=target, live=self.query_one("#live", Checkbox).value)
        scope_id = self.query_one("#scope", Input).value.strip() or None
        plugin = self.query_one("#plugin", Input).value.strip()
        try:
            if plugin:
                result = collect_named(settings, plugin, ctx, scope_id=scope_id)
            elif target:
                result = collect_target(settings, target, ctx, checkpoint=True, scope_id=scope_id)
            else:
                result = collect_all(settings, ctx, checkpoint=True, scope_id=scope_id)
            # Show each run's mode so a fixture or failed live run is never read as live evidence.
            runs = result.get("runs") if "runs" in result else [result]
            self.notify("collected " + (", ".join(f"{run.get('plugin')}={run.get('mode')}" for run in runs) or "nothing"))
        except BeaconError as exc:
            self.notify(f"{exc.code}: {exc.message}", severity="error")
        self.current = "dashboard"
        self.refresh_pane()

    def _push(self) -> None:
        try:
            path = write_pack(load_settings(), None)
            self.notify(f"wrote {path.path}")
        except BeaconError as exc:
            self.notify(f"{exc.code}: {exc.message}", severity="error")
        self.current = "push"
        self.refresh_pane()


def run_tui(*, skip_tour: bool = False) -> None:
    BeaconTUI(skip_tour=skip_tour_requested(skip_tour)).run()
