"""Dangerous / over-broad capability rules (MCPS010–013).

Capabilities are inferred from a tool's name, description, and parameter names.
"""
from __future__ import annotations

import re

from ..models import Finding, Location, ScanTarget
from .base import finding, iter_tools, param_names, tool_text

_EXEC = re.compile(r"\b(exec|shell|bash|sh|command|run_code|eval|subprocess|os\.system)\b", re.I)
_WRITE = re.compile(r"\b(write_file|delete|rm|unlink|put_file|save|overwrite)\b", re.I)
_NET = re.compile(r"\b(fetch|http_request|curl|request|webhook|upload|download|post)\b", re.I)
_CRED = re.compile(
    r"\b(get_env|read_secret|credentials?|tokens?|keychain|password|dotenv|aws_credentials)\b", re.I
)


def _hay(t) -> str:
    return f"{t.name}\n{tool_text(t)}"


def check_mcps010(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        if _EXEC.search(_hay(t)) or ({"command", "cmd", "script"} & param_names(t)):
            out.append(finding("MCPS010",
                f"tool '{t.name}' exposes a shell/exec capability",
                Location(server=s.name, tool=t.name, field="name")))
    return out


def check_mcps011(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        params = param_names(t)
        write_kw = _WRITE.search(_hay(t))
        path_content = {"path"} <= params and {"content", "data", "text"} & params
        if write_kw or path_content:
            out.append(finding("MCPS011",
                f"tool '{t.name}' can write or delete arbitrary files",
                Location(server=s.name, tool=t.name, field="name")))
    return out


def check_mcps012(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        if _NET.search(_hay(t)) or ("url" in param_names(t)):
            out.append(finding("MCPS012",
                f"tool '{t.name}' performs unbounded network egress",
                Location(server=s.name, tool=t.name, field="name")))
    return out


def check_mcps013(target: ScanTarget) -> list[Finding]:
    out = []
    for s, t in iter_tools(target):
        if _CRED.search(_hay(t)):
            out.append(finding("MCPS013",
                f"tool '{t.name}' reads credentials/secrets directly",
                Location(server=s.name, tool=t.name, field="name")))
    return out


CHECKS = {
    "MCPS010": check_mcps010,
    "MCPS011": check_mcps011,
    "MCPS012": check_mcps012,
    "MCPS013": check_mcps013,
}
