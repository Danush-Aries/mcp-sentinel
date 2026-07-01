"""Loader for client ``settings.json`` files (Claude Desktop / Cursor / etc.).

Shape::

    {"mcpServers": {"<name>": {"command", "args", "env", "url"?,
                               "description"?, "tools"?: [...]}}}
"""
from __future__ import annotations

import json

from ..engine import InputError
from ..models import ScanTarget
from .normalize import server_from_settings_entry


def load(path: str) -> ScanTarget:
    """Load an mcpServers settings file into a ``kind="settings"`` ScanTarget.

    Raises :class:`InputError` on missing file, invalid JSON, or a document that
    lacks a top-level ``mcpServers`` object.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError as exc:
        raise InputError(f"settings file not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not read settings file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in settings file {path}: {exc}") from exc

    servers_raw = doc.get("mcpServers") if isinstance(doc, dict) else None
    if not isinstance(servers_raw, dict):
        raise InputError(
            f"settings file {path} has no top-level 'mcpServers' object"
        )

    servers = [
        server_from_settings_entry(name, entry or {}, path)
        for name, entry in servers_raw.items()
    ]
    return ScanTarget(kind="settings", path=path, servers=servers)
