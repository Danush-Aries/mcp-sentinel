"""Severity scale + its mappings to SARIF levels and process exit codes."""
from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def sarif_level(self) -> str:
        # SARIF only has note/warning/error.
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]
