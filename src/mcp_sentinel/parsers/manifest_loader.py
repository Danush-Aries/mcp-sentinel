"""Loader for a standalone MCP server manifest.

Shape::

    {"name": "...", "version": "...", "description": "...",
     "tools": [{"name", "description", "parameters"}, ...]}

The whole document is treated as a single server whose tools are declared inline.
"""
from __future__ import annotations

import json

from ..engine import InputError
from ..models import ScanTarget, ServerSpec
from .normalize import tool_from_dict


def load(path: str) -> ScanTarget:
    """Load an MCP manifest into a ``kind="manifest"`` ScanTarget (one server)."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError as exc:
        raise InputError(f"manifest file not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not read manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in manifest {path}: {exc}") from exc

    if not isinstance(doc, dict):
        raise InputError(f"manifest {path} is not a JSON object")

    server = ServerSpec(
        name=str(doc.get("name", "(manifest)")),
        declared_purpose=str(doc.get("description", "")),
        tools=[tool_from_dict(t) for t in doc.get("tools", []) or []],
        source_path=path,
        raw=doc,
    )
    return ScanTarget(kind="manifest", path=path, servers=[server])
