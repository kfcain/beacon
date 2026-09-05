"""Paramify-style TUI: Dashboard, Freshness, Validation, Push, System, Collect."""

from __future__ import annotations

from typing import Any, Literal, assert_never

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Static

from beacon.config import load_settings
from beacon.errors import BeaconError
from beacon.plugins.spec import CollectContext
from beacon.push import write_pack
from beacon.scf.engine import collect_all, collect_target
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

OK = "#9ECE6A"
FAIL = "#F7768E"
MUTED = "#565F89"
CYAN = "#7DCFFF"
PURPLE = "#BB9AF7"


def _status_line() -> Text:
    data = validation(load_settings())
    text = Text()
    text.append("Beacon  ", style=f"bold {PURPLE}")
    if data.get("ok"):
        text.append("VALIDATION OK", style=f"bold {OK}")
    else:
        text.append(str(data.get("code") or "FAIL"), style=f"bold {FAIL}")
        if data.get("message"):
            text.append(f"  {data['message']}", style=MUTED)
    return text


def _kv(label: str, value: Any) -> str:
    return f"[cyan]{label}[/]\n{value}\n"


class Pane(Static):
    DEFAULT_CSS = "Pane { width: 1fr; height: 1fr; padding: 1 2; background: #16161e; }"


class BeaconTUI(App[None]):
    """Keyboard-first evidence console."""

    TITLE = "Beacon"
    CSS = """
    Screen { background: #1a1b26; }
    #tabs { height: 3; dock: top; }
    #tabs Button { margin: 0 1; }
    #body { height: 1fr; }
    Input { margin: 1 0; }
    """
    BINDINGS = [
        ("1", "show('dashboard')", "Dashboard"),
        ("2", "show('freshness')", "Freshness"),
        ("3", "show('validation')", "Validation"),
        ("4", "show('push')", "Push"),
        ("5", "show('system')", "System"),
        ("6", "show('collect')", "Collect"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.current: ScreenName = "dashboard"

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="tabs"):
            yield Button("Dashboard", id="tab-dashboard")
            yield Button("Freshness", id="tab-freshness")
            yield Button("Validation", id="tab-validation")
            yield Button("Push", id="tab-push")
            yield Button("System", id="tab-system")
            yield Button("Collect", id="tab-collect")
        with VerticalScroll(id="body"):
            yield Pane(id="pane")
        with Horizontal():
            yield Input(placeholder="SCF target (IAC-01 / CRY-05) or empty for all", id="target")
            yield Button("Collect", id="do-collect", variant="primary")
            yield Button("Push pack", id="do-push")
            yield Button("Recheck", id="do-check")
        yield Footer()

    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        self.refresh_pane()

    def action_show(self, name: str) -> None:
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
        if bid == "do-collect":
            self._collect()
            return
        if bid == "do-push":
            self._push()
            return
        if bid == "do-check":
            self.current = "validation"
            self.refresh_pane()

    def refresh_pane(self) -> None:
        pane = self.query_one("#pane", Pane)
        settings = load_settings()
        current = self.current
        match current:
            case "dashboard":
                pane.update(self._dashboard(settings))
            case "freshness":
                pane.update(self._freshness())
            case "validation":
                pane.update(self._validation())
            case "push":
                pane.update("[cyan]Push[/]\nExport a sealed pack with public keys only.\nPress Push pack.")
            case "system":
                pane.update(self._system(settings))
            case "collect":
                pane.update(
                    "[cyan]Collect[/]\n"
                    "Enter an SCF id (IAC-01, CRY-05) or leave empty to run every overlapping fetcher.\n"
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
            "[cyan]Dashboard[/]\n"
            f"records={status.get('records')}  checkpoints={status.get('checkpoints')}  "
            f"covered={chain.get('covered_through')}\n"
            f"SCF {status.get('scf_version')}  offline={status.get('scf_offline')}\n\n"
            f"[cyan]Plugins[/]\n{plugins or '  (none)'}"
        )

    def _freshness(self) -> str:
        rows = freshness(load_settings())
        if not rows:
            return "[cyan]Freshness[/]\nNo sealed evidence. Run seed or collect."
        lines = ["[cyan]Freshness[/]"]
        for item in rows:
            lines.append(f"  {item['plugin']:18}  {item['mode']:12}  seq={item['seq']}  {item['ts']}")
        return "\n".join(lines)

    def _validation(self) -> str:
        data = validation(load_settings())
        mark = "OK" if data.get("ok") else str(data.get("code"))
        return f"[cyan]Validation[/]\n{mark}\n{data}"

    def _system(self, settings) -> str:
        status = system_status(settings)
        return (
            "[cyan]System[/]\n"
            + _kv("home", status.get("home"))
            + _kv("recorder", status.get("recorder_fingerprint"))
            + _kv("witness", status.get("witness_fingerprint"))
            + _kv("keys_distinct", status.get("keys_distinct"))
            + _kv("scf_api_base", status.get("scf_api_base"))
        )

    def _collect(self) -> None:
        target = self.query_one("#target", Input).value.strip() or None
        settings = load_settings()
        ctx = CollectContext(target=target)
        try:
            if target:
                result = collect_target(settings, target, ctx, checkpoint=True)
            else:
                result = collect_all(settings, ctx, checkpoint=True)
            self.notify(f"collected plugins={result.get('plugins') or [r.get('plugin') for r in result.get('runs', [])]}")
        except BeaconError as exc:
            self.notify(f"{exc.code}: {exc.message}", severity="error")
        self.current = "dashboard"
        self.refresh_pane()

    def _push(self) -> None:
        try:
            path = write_pack(load_settings(), None)
            self.notify(f"wrote {path}")
        except BeaconError as exc:
            self.notify(f"{exc.code}: {exc.message}", severity="error")
        self.current = "push"
        self.refresh_pane()


def run_tui() -> None:
    BeaconTUI().run()
