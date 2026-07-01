"""Least-privilege / scope rules (MCPS040–041)."""
from __future__ import annotations

import re

from ..models import Finding, Location, ScanTarget, ServerSpec
from .base import finding, param_names
from .capabilities import check_mcps010, check_mcps011, check_mcps013

_READONLY = re.compile(r"\b(read|read-only|search|lookup|weather|docs|documentation|query|browse)\b", re.I)
_MAX_TOOLS = 25


def _has_high_capability(server: ServerSpec) -> bool:
    t = ScanTarget(kind="settings", path="", servers=[server])
    return bool(check_mcps010(t) or check_mcps011(t) or check_mcps013(t))


def check_mcps040(target: ScanTarget) -> list[Finding]:
    out = []
    for s in target.servers:
        if s.declared_purpose and _READONLY.search(s.declared_purpose) and _has_high_capability(s):
            out.append(finding("MCPS040",
                f"server '{s.name}' declares a read-only purpose but exposes exec/write/secret tools",
                Location(server=s.name, field="declared_purpose",
                         snippet=s.declared_purpose[:60])))
    return out


def check_mcps041(target: ScanTarget) -> list[Finding]:
    out = []
    for s in target.servers:
        if len(s.tools) > _MAX_TOOLS:
            out.append(finding("MCPS041",
                f"server '{s.name}' exposes {len(s.tools)} tools (> {_MAX_TOOLS}); review least privilege",
                Location(server=s.name, field="tools")))
            continue
        for t in s.tools:
            if "*" in param_names(t):
                out.append(finding("MCPS041",
                    f"tool '{t.name}' on server '{s.name}' uses a wildcard parameter scope",
                    Location(server=s.name, tool=t.name, field="parameters")))
                break
    return out


CHECKS = {
    "MCPS040": check_mcps040,
    "MCPS041": check_mcps041,
}
