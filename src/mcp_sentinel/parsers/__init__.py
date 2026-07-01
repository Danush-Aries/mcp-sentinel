"""Input parsing: turn any supported artifact into a normalized ScanTarget."""
from __future__ import annotations

import json

from ..engine import InputError
from ..models import ScanTarget
from . import manifest_loader, settings_loader, stdio_probe

__all__ = ["load_target"]


def load_target(path: str, kind: str = "auto") -> ScanTarget:
    """Load ``path`` into a ScanTarget.

    kind: "settings" | "manifest" | "stdio" forces a loader. "auto" sniffs the
    JSON shape — a top-level ``mcpServers`` object => settings; a document with
    ``name`` + ``tools`` => manifest.
    """
    if kind == "settings":
        return settings_loader.load(path)
    if kind == "manifest":
        return manifest_loader.load(path)
    if kind == "stdio":
        return stdio_probe.load(path)
    if kind != "auto":
        raise InputError(f"unknown input kind: {kind}")

    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError as exc:
        raise InputError(f"file not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path}: {exc}") from exc

    if isinstance(doc, dict) and isinstance(doc.get("mcpServers"), dict):
        return settings_loader.load(path)
    if isinstance(doc, dict) and "tools" in doc and "name" in doc:
        return manifest_loader.load(path)
    raise InputError(
        f"could not autodetect MCP input shape for {path} "
        "(expected 'mcpServers' or a manifest with 'name' + 'tools')"
    )
