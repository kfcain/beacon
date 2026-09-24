"""Walkthrough steps and the first-run flag for the Beacon TUI.

The tour is guidance. It does not collect, check, or push, and it does not
add assurance. A seal is not "control met".
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from beacon.config import env
from beacon.scf.catalog_pin import PINNED_SCF_VERSION

TourFocus = Literal["dashboard", "freshness", "validation", "push", "system", "collect"]
TOUR_SEEN_NAME = "tui_tour_seen"

# 2026.3 offline seeds. Titles match beacon/scf/offline/*.json. Do not reuse
# the pre-remap ids for these seeds.
_SEED_IAM = "IAC-02"
_SEED_AT_REST = "CRY-07"


@dataclass(frozen=True)
class TourStep:
    """One walkthrough card and the live tab it points at."""

    id: str
    title: str
    body: str
    focus: TourFocus


def _steps() -> tuple[TourStep, ...]:
    pin = PINNED_SCF_VERSION
    return (
        TourStep(
            id="what",
            title="What Beacon is",
            focus="dashboard",
            body=(
                "Beacon is an evidence engine.\n"
                "It collects observations and seals each result on a signed witness chain.\n"
                "A seal records the writer and the order of the bytes.\n"
                'A seal is not "control met".\n'
                "Beacon does not give an audit opinion."
            ),
        ),
        TourStep(
            id="dashboard",
            title="Dashboard",
            focus="dashboard",
            body=(
                "Plugins and an SCF version line are on this tab.\n"
                "The SCF line is the control-slice version.\n"
                "That version is often 2026.1.1.\n"
                f"The catalog pin is SCF {pin}. HackIDLE is not the pin.\n"
                "A plugin row is a label. It is not a control result.\n"
                "Press ? or h, or Tour, to open this walkthrough again."
            ),
        ),
        TourStep(
            id="collect",
            title="Collect",
            focus="collect",
            body=(
                f"On catalog pin {pin}, seeds are {_SEED_IAM} and {_SEED_AT_REST}.\n"
                f"{_SEED_IAM} is Identity & Access Management (IAM).\n"
                f"{_SEED_AT_REST} is Encrypting Data At Rest.\n"
                "An id runs the fetchers that overlap that target.\n"
                'An empty field runs every loaded collector. A record is not "control met".'
            ),
        ),
        TourStep(
            id="validation",
            title="Validation",
            focus="validation",
            body=(
                "This tab runs the same check as beacon check.\n"
                'VALIDATION OK is not "control met".\n'
                "The witness chain fails closed.\n"
                "No Merkle/TSA checkpoint returns E_NO_CHECKPOINT.\n"
                "VALIDATION OK means the links and the checkpoints cover the records in this workspace."
            ),
        ),
        TourStep(
            id="freshness",
            title="Freshness",
            focus="freshness",
            body=(
                "Freshness lists the latest sealed row for each plugin.\n"
                "Each row shows the plugin, the mode, the sequence, and the time.\n"
                "An empty list means this workspace has no sealed rows yet. Run seed or collect.\n"
                "A recent timestamp does not show that the observation is true."
            ),
        ),
        TourStep(
            id="push",
            title="Push pack",
            focus="push",
            body=(
                "Push pack writes a local sealed pack.\n"
                "The pack holds records, checkpoints, and public keys.\n"
                "Private keys stay in .beacon/keys. The pack does not include them.\n"
                "Press Push pack on this screen when you want the file."
            ),
        ),
        TourStep(
            id="lake",
            title="Evidence lake (optional)",
            focus="push",
            body=(
                "When BEACON_S3_BUCKET is set, collect and push also write the sealed artifacts to that bucket.\n"
                "This walkthrough does not need AWS. Leave the variable unset and Beacon stays on this machine.\n"
                "Private keys, config.json, and cache/ are not uploaded.\n"
                'A remote copy is stored bytes. It is not "control met".'
            ),
        ),
        TourStep(
            id="system",
            title="System",
            focus="system",
            body=(
                "System shows the workspace fingerprints.\n"
                "beacon init creates two keys: a recorder key and a witness key.\n"
                "keys_distinct is true when both fingerprints exist and they differ.\n"
                "A fingerprint identifies a key. It is not an audit opinion."
            ),
        ),
    )


TOUR_STEPS: tuple[TourStep, ...] = _steps()


@dataclass
class TourCursor:
    """Index into TOUR_STEPS. Next and Back stay inside the list."""

    index: int = 0

    def __post_init__(self) -> None:
        last = len(TOUR_STEPS) - 1
        if self.index < 0:
            self.index = 0
        elif self.index > last:
            self.index = last

    @property
    def step(self) -> TourStep:
        return TOUR_STEPS[self.index]

    @property
    def total(self) -> int:
        return len(TOUR_STEPS)

    @property
    def at_start(self) -> bool:
        return self.index == 0

    @property
    def at_end(self) -> bool:
        return self.index == len(TOUR_STEPS) - 1

    def next(self) -> TourStep:
        if not self.at_end:
            self.index += 1
        return self.step

    def back(self) -> TourStep:
        if not self.at_start:
            self.index -= 1
        return self.step

    def restart(self) -> TourStep:
        self.index = 0
        return self.step


def tour_seen_path(home: Path) -> Path:
    return home / TOUR_SEEN_NAME


def is_tour_seen(home: Path) -> bool:
    return tour_seen_path(home).is_file()


def mark_tour_seen(home: Path) -> Path:
    path = tour_seen_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("seen\n", encoding="utf-8")
    return path


def skip_tour_requested(cli_no_tour: bool = False) -> bool:
    """True when the user asked to skip the auto-start walkthrough."""
    if cli_no_tour:
        return True
    raw = env("NO_TOUR")
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def should_auto_start_tour(home: Path, *, skip: bool) -> bool:
    """Open the walkthrough on launch when this workspace has not seen it."""
    if skip:
        return False
    return not is_tour_seen(home)
