"""Tool-poisoning / prompt-injection rules (MCPS001–004).

These operate on the model-visible text of a tool — its description and parameter
descriptions — which MCP injects verbatim into the LLM context.
"""
from __future__ import annotations

import re

from ..models import Finding, Location, ScanTarget
from .base import find_base64_blob, finding, has_invisible_unicode, iter_tools, tool_text

_OVERRIDE = re.compile(
    r"ignore\s+(all\s+)?previous|disregard\s+(the\s+)?instructions|you\s+are\s+now|"
    r"system\s+prompt|do\s+not\s+tell\s+the\s+user|<important>|\[\[",
    re.IGNORECASE,
)
_HIDDEN = re.compile(
    r"do\s+not\s+mention|without\s+telling|send\s+.*\s+to\b|exfiltrate|"
    r"forward\s+.*\s+to\s+http",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def check_mcps001(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        m = _OVERRIDE.search(tool_text(t))
        if m:
            out.append(finding("MCPS001",
                f"tool '{t.name}' description contains an instruction-override phrase: "
                f"'{m.group(0)}'",
                Location(server=s.name, tool=t.name, field="description",
                         snippet=_excerpt(tool_text(t), m.start()))))
    return out


def check_mcps002(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        if has_invisible_unicode(tool_text(t)):
            out.append(finding("MCPS002",
                f"tool '{t.name}' description contains invisible/control unicode characters",
                Location(server=s.name, tool=t.name, field="description",
                         snippet="<invisible characters present>")))
    return out


def check_mcps003(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        blob = find_base64_blob(tool_text(t))
        if blob:
            out.append(finding("MCPS003",
                f"tool '{t.name}' description embeds an encoded (base64) payload blob",
                Location(server=s.name, tool=t.name, field="description",
                         snippet=blob[:24] + "…")))
    return out


def check_mcps004(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        text = tool_text(t)
        m = _HIDDEN.search(text)
        if m:
            out.append(finding("MCPS004",
                f"tool '{t.name}' description contains hidden-channel/exfiltration language: "
                f"'{m.group(0)}'",
                Location(server=s.name, tool=t.name, field="description",
                         snippet=_excerpt(text, m.start()))))
    return out


def _excerpt(text: str, at: int, width: int = 40) -> str:
    start = max(0, at - 5)
    return text[start:start + width].replace("\n", " ").strip()


CHECKS = {
    "MCPS001": check_mcps001,
    "MCPS002": check_mcps002,
    "MCPS003": check_mcps003,
    "MCPS004": check_mcps004,
}
