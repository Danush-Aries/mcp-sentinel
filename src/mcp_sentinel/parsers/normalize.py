"""Pure coercion helpers: raw dicts -> frozen model instances.

These functions are the single place that knows how a client's JSON shape maps
onto the :class:`ServerSpec` / :class:`ToolSpec` contract. They are deliberately
tolerant: a sparse-but-well-formed entry must never raise. Only the loaders (which
own file/JSON I/O) raise :class:`InputError`.
"""
from __future__ import annotations

from ..models import ServerSpec, ToolSpec


def tool_from_dict(d: dict) -> ToolSpec:
    """Coerce a raw tool dict into a :class:`ToolSpec`.

    ``name`` is the only meaningful field; ``description`` and ``parameters`` are
    optional. The original dict is preserved verbatim in ``raw`` for evidence.
    """
    return ToolSpec(
        name=str(d.get("name", "")),
        description=str(d.get("description", "")),
        parameters=d.get("parameters", {}) or {},
        raw=d,
    )


def server_from_settings_entry(name: str, entry: dict, source_path: str) -> ServerSpec:
    """Coerce one ``mcpServers`` entry into a :class:`ServerSpec`.

    Missing keys are tolerated: ``args``/``env`` default empty, ``tools`` is only
    parsed when present. ``declared_purpose`` comes from the entry ``description``.
    """
    tools = [tool_from_dict(t) for t in entry.get("tools", []) or []]
    return ServerSpec(
        name=name,
        command=entry.get("command"),
        args=list(entry.get("args", []) or []),
        env=dict(entry.get("env", {}) or {}),
        url=entry.get("url"),
        declared_purpose=str(entry.get("description", "")),
        tools=tools,
        source_path=source_path,
        raw=entry,
    )
