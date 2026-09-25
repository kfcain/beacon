"""Paramify-style TUI: Dashboard, Freshness, Validation, Push, System, Collect."""

from __future__ import annotations

from typing import Any, Literal, assert_never

import json
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, HorizontalScroll, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Footer, Header, Input, Select, Static

from beacon.config import load_settings
from beacon.errors import BeaconError
from beacon.plugins.spec import CollectContext
from beacon.push import write_pack
from beacon.scf.engine import collect_all, collect_target, collect_named
from beacon.assurance.evaluation import evaluate_control
from beacon.assurance.assessments import evaluate_assessment, list_assessments, record_review, refresh_assessments, review_queue
from beacon.assurance.specs import list_specs
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


def _assessment_text(row: dict[str, Any]) -> Text:
    """Render untrusted evidence as literal text, with eligibility and gaps visible."""
    receipt = row.get("receipt") or {}
    text = Text()
    text.append(str(receipt.get("spec_id") or "Assessment"), style=f"bold {BLUE_TEXT}")
    status = str(receipt.get("status") or "not assessed")
    if status == "supporting_pass":
        status = "Checks passed (supporting)"
    text.append(f"\n{status.replace('_', ' ')} · scope {receipt.get('scope_id', '')}\n")
    text.append(f"Control {receipt.get('control_ref', 'unspecified')} / objective {receipt.get('ao_id', 'unspecified')} · {str(receipt.get('time_basis', 'unspecified time basis')).replace('_', ' ')}\n")
    if row.get("current") is False:
        text.append("REEVALUATION REQUIRED\n", style="bold yellow")
        for reason in row.get("invalidation_reasons") or []:
            text.append(f"  • {reason}\n")
    text.append("Objective and control satisfaction remain unset.\n\n")

    def append_value(value: Any, depth: int = 1) -> None:
        indent = "  " * depth
        if isinstance(value, dict):
            for key, item in value.items():
                text.append(f"{indent}{str(key).replace('_', ' ')}: ", style=BLUE_TEXT)
                if isinstance(item, (dict, list)):
                    text.append("\n")
                    append_value(item, depth + 1)
                else:
                    text.append(f"{item}\n")
        elif isinstance(value, list):
            if not value:
                text.append(f"{indent}None recorded\n")
            for item in value:
                if isinstance(item, (dict, list)):
                    append_value(item, depth)
                    text.append("\n")
                else:
                    text.append(f"{indent}• {item}\n")
        else:
            text.append(f"{indent}{value}\n")

    for title, value in (
        ("Criteria", receipt.get("results") or []),
        ("Gaps and next steps", receipt.get("gaps") or []),
        ("Findings", receipt.get("findings") or []),
        ("Operator review (local OS account)", row.get("review") or "No review recorded."),
        ("Receipt provenance", {
            "evidence_id": row.get("evidence_id") or receipt.get("receipt_evidence_id"),
            "evaluated_at": receipt.get("evaluated_at"),
            "spec_sha256": receipt.get("spec_sha256"),
            "objective_sha256": receipt.get("objective_sha256"),
            "catalog_sha256": receipt.get("catalog_sha256"),
            "input_sha256": receipt.get("input_sha256"),
            "expires_at": receipt.get("expires_at"),
        }),
    ):
        text.append(f"{title}\n", style=f"bold {BLUE_TEXT}")
        append_value(value)
        text.append("\n")
    return text


class AssessmentScreen(ModalScreen[None]):
    """Local assessment and review workspace; approval identity is OS-derived."""

    DEFAULT_CSS = """
    AssessmentScreen { background: $background; }
    #assessment-workspace { height: 1fr; padding: 1 2; }
    #assessment-heading { color: $primary-lighten-2; text-style: bold; height: auto; }
    #assessment-description, #assessment-notice, #assessment-spec-note { height: auto; margin-bottom: 1; }
    .assessment-row { height: 3; margin-bottom: 1; }
    .assessment-row Button { width: auto; min-width: 0; padding: 0 1; margin-right: 1; }
    #assessment-scope { width: 1fr; }
    #assessment-spec, #assessment-receipt { margin-bottom: 1; }
    #assessment-result { height: auto; padding: 1; background: $surface; }
    #assessment-review-label { height: auto; margin-top: 1; }
    #assessment-rationale { margin-bottom: 1; }
    #assessment-close-row { height: 3; padding-left: 2; }
    """
    BINDINGS = [Binding("escape", "close", "Close")]

    def __init__(self, scope_id: str = "") -> None:
        super().__init__()
        self.scope_id = scope_id
        self.rows: list[dict[str, Any]] = []
        self.specs: list[dict[str, Any]] = []
        self.queue_only = False

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="assessment-workspace"):
            yield Static("Requirement assessments", id="assessment-heading")
            yield Static("Approved criteria + sealed evidence. Supporting results do not establish objective or control satisfaction.", id="assessment-description")
            with Horizontal(classes="assessment-row"):
                yield Input(value=self.scope_id, placeholder="Enrolled scope id", id="assessment-scope")
                yield Button("Load scope", id="assessment-load")
            yield Select([], prompt="Approved specification", id="assessment-spec")
            yield Static("", id="assessment-spec-note")
            with Horizontal(classes="assessment-row"):
                yield Button("Assess selected", id="assessment-run", variant="primary", disabled=True)
                yield Button("Reevaluate", id="assessment-refresh", disabled=True)
                yield Button("Latest", id="assessment-all")
                yield Button("Review queue", id="assessment-queue")
            yield Static("", id="assessment-notice")
            yield Select([], prompt="Select receipt to inspect", id="assessment-receipt")
            yield Static("Load a scope to see specifications and assessment receipts.", id="assessment-result")
            yield Static("Operator review: enter a rationale. The scope must approve this OS account. The record shows the account, not proof that a person acted. Acceptance cannot override failed or missing evidence.", id="assessment-review-label")
            yield Input(placeholder="Review rationale with source citations (10–4000 characters)", id="assessment-rationale", max_length=4000)
            with Horizontal(classes="assessment-row"):
                yield Button("Accept supporting assessment", id="assessment-accept", disabled=True)
                yield Button("Reject assessment", id="assessment-reject", disabled=True)
        with Horizontal(id="assessment-close-row"):
            yield Button("Close · Esc", id="assessment-close")

    def on_mount(self) -> None:
        if self.scope_id:
            self.load_workspace()

    def action_close(self) -> None:
        self.dismiss()

    def _notice(self, message: str, *, error: bool = False) -> None:
        self.query_one("#assessment-notice", Static).update(Text(message, style=FAIL if error else MUTED))

    def _selected_row(self) -> dict[str, Any] | None:
        selected = self.query_one("#assessment-receipt", Select).value
        return next((row for row in self.rows if row.get("evidence_id") == selected), None)

    def load_workspace(self, preferred_id: str | None = None) -> None:
        scope_id = self.query_one("#assessment-scope", Input).value.strip()
        self.rows = []
        self.specs = []
        old_spec = self.query_one("#assessment-spec", Select).value
        for key in ("run", "refresh", "accept", "reject"):
            self.query_one(f"#assessment-{key}", Button).disabled = True
        self.query_one("#assessment-spec", Select).set_options([])
        self.query_one("#assessment-receipt", Select).set_options([])
        self.query_one("#assessment-result", Static).update("Select a receipt to inspect criteria, evidence references, and gaps.")
        if not scope_id:
            self._notice("Enter an enrolled scope id. No requirement has been assessed.")
            return
        try:
            settings = load_settings()
            self.specs = [item for item in list_specs(settings, scope_id=scope_id) if item.get("approved") is True]
            self.rows = (review_queue if self.queue_only else list_assessments)(settings, scope_id=scope_id)
            self.scope_id = scope_id
            spec_widget = self.query_one("#assessment-spec", Select)
            spec_widget.set_options([
                (f"{item['spec']['spec_id']} · {item['spec_sha256'][:12]}", item["spec_sha256"])
                for item in self.specs
            ])
            if self.specs:
                hashes = {item["spec_sha256"] for item in self.specs}
                spec_widget.value = old_spec if old_spec in hashes else self.specs[0]["spec_sha256"]
            else:
                self.query_one("#assessment-spec-note", Static).update("No approved specification. Import one with beacon assessment-spec-import, then approve its hash in the scope.")
            receipt_widget = self.query_one("#assessment-receipt", Select)
            receipt_widget.set_options([
                (f"{row['receipt'].get('spec_id')} · {'reevaluation required' if not row.get('current') else row['receipt'].get('status')} · {str(row['evidence_id'])[:12]}", row["evidence_id"])
                for row in self.rows
            ])
            if preferred_id and any(row["evidence_id"] == preferred_id for row in self.rows):
                receipt_widget.value = preferred_id
            self.query_one("#assessment-refresh", Button).disabled = False
            if not self.rows:
                self._notice("No queued receipts. This does not indicate that every requirement has been assessed." if self.queue_only else "No assessment receipts. Select an approved specification to assess.")
            else:
                self._notice(f"{len(self.rows)} {'queued' if self.queue_only else 'latest'} receipt(s). Reevaluation uses sealed evidence; no live collection is requested.")
        except BeaconError as exc:
            self.rows = []
            self.specs = []
            self.query_one("#assessment-spec-note", Static).update("Specification approval state unavailable.")
            self._notice(str(exc), error=True)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "assessment-spec":
            item = next((item for item in self.specs if item["spec_sha256"] == event.value), None)
            self.query_one("#assessment-run", Button).disabled = item is None
            if item:
                self.query_one("#assessment-spec-note", Static).update(Text(f"{item['spec'].get('title', item['spec']['spec_id'])}\nSHA-256 {item['spec_sha256']}"))
        elif event.select.id == "assessment-receipt":
            row = self._selected_row()
            if row:
                self.query_one("#assessment-result", Static).update(_assessment_text(row))
            receipt = (row or {}).get("receipt") or {}
            can_accept = bool(row and row.get("current") and receipt.get("status") in {"supporting_pass", "needs_review"}
                              and not receipt.get("gaps") and not receipt.get("findings"))
            self.query_one("#assessment-accept", Button).disabled = not can_accept
            self.query_one("#assessment-reject", Button).disabled = row is None
            self.query_one("#assessment-rationale", Input).value = ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        bid = event.button.id
        if bid == "assessment-close":
            self.dismiss()
            return
        if bid in {"assessment-load", "assessment-all", "assessment-queue"}:
            if bid != "assessment-load":
                self.queue_only = bid == "assessment-queue"
            self.load_workspace()
            return
        # Scope selection must be reloaded before a mutation. It cannot silently
        # retarget an already displayed specification or receipt.
        if self.query_one("#assessment-scope", Input).value.strip() != self.scope_id:
            self._notice("Scope changed. Load it before assessing or reviewing.", error=True)
            return
        try:
            settings = load_settings()
            if bid == "assessment-run":
                spec_hash = self.query_one("#assessment-spec", Select).value
                if not isinstance(spec_hash, str):
                    self._notice("Select an approved specification first.", error=True)
                    return
                receipt = evaluate_assessment(settings, scope_id=self.scope_id, spec_sha256=spec_hash)
                self.queue_only = False
                self.load_workspace(receipt.get("receipt_evidence_id"))
            elif bid == "assessment-refresh":
                result = refresh_assessments(settings, scope_id=self.scope_id, collect_missing=False)
                self.load_workspace()
                self._notice(f"Reevaluation completed: {len(result.get('evaluations') or [])} new receipts; {result.get('unchanged', 0)} unchanged. No live collection requested.")
            elif bid in {"assessment-accept", "assessment-reject"}:
                row = self._selected_row()
                rationale = self.query_one("#assessment-rationale", Input).value.strip()
                if not row or not rationale:
                    self._notice("Select a receipt and enter the required review rationale.", error=True)
                    return
                record_review(settings, receipt_evidence_id=row["evidence_id"], decision="accept" if bid == "assessment-accept" else "reject", rationale=rationale)
                self.load_workspace(row["evidence_id"])
                self._notice("Operator review recorded for this OS account. Objective and control satisfaction remain unset.")
        except BeaconError as exc:
            self._notice(str(exc), error=True)


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
        ("7", "assessments", "Assessments"),
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
        with HorizontalScroll(id="tabs"):
            yield Button("Dashboard", id="tab-dashboard")
            yield Button("Freshness", id="tab-freshness")
            yield Button("Validation", id="tab-validation")
            yield Button("Push", id="tab-push")
            yield Button("System", id="tab-system")
            yield Button("Collect", id="tab-collect")
            yield Button("Tour", id="do-tour")
            yield Button("Assessments", id="do-assessments")
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

    def action_assessments(self) -> None:
        self.push_screen(AssessmentScreen(self.query_one("#scope", Input).value.strip()))

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
        if bid == "do-assessments":
            self.action_assessments()
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
            "Press 7 for requirement assessments and operator review; ? for the walkthrough.\n\n"
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
