"""Live stdio probing (P3, not implemented in v0.1.0).

The intended design: spawn the configured MCP server as a subprocess, perform the
JSON-RPC ``initialize`` handshake, call ``tools/list``, and feed the returned tool
schemas into the same rule engine used for static scans. This gives coverage of
servers whose tool descriptions are only visible at runtime. It is deferred to keep
v0.1.0 fully offline and dependency-light.
"""
from __future__ import annotations

from ..engine import InputError
from ..models import ScanTarget


def load(path: str) -> ScanTarget:
    raise InputError("stdio probing is not available in v0.1.0 (planned P3 feature)")
