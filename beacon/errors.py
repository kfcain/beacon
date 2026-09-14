"""Typed Beacon errors. Checkers match on ``code``."""

from __future__ import annotations

from typing import NoReturn


class BeaconError(Exception):
    """Operational error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


E_NO_CHECKPOINT = "E_NO_CHECKPOINT"
E_BAD_CHAIN = "E_BAD_CHAIN"
E_BAD_SIGNATURE = "E_BAD_SIGNATURE"
E_KEY_COLLISION = "E_KEY_COLLISION"
E_NOT_INITIALIZED = "E_NOT_INITIALIZED"
E_ALREADY_INITIALIZED = "E_ALREADY_INITIALIZED"
E_LIVE_FAILED = "E_LIVE_FAILED"
E_UNKNOWN_PLUGIN = "E_UNKNOWN_PLUGIN"
E_UNKNOWN_CONTROL = "E_UNKNOWN_CONTROL"
E_TSA = "E_TSA"
E_SCF = "E_SCF"
E_CONTROL_MISMATCH = "E_CONTROL_MISMATCH"
E_REMOTE = "E_REMOTE"


def fail(code: str, message: str) -> NoReturn:
    raise BeaconError(code, message)
