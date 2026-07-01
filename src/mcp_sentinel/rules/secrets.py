"""Secret-exposure rules (MCPS020–022). Scan server env values and args.

Evidence is always masked in the emitted Location.snippet — the raw secret never
appears in a report.
"""
from __future__ import annotations

import re

from ..models import Finding, Location, ScanTarget
from .base import finding, iter_env, mask_secret, shannon_entropy

# (label, compiled regex) — anthropic before openai so sk-ant- is labelled correctly.
_PROVIDERS: list[tuple[str, re.Pattern]] = [
    ("Anthropic", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("OpenAI", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("GitHub", re.compile(r"gh[posru]_[A-Za-z0-9]{36}")),
    ("AWS", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Slack", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitLab", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")),
    ("HuggingFace", re.compile(r"hf_[A-Za-z0-9]{30,}")),
]
_SECRET_NAME = re.compile(r"(key|token|secret|passwd|password|auth|api)", re.IGNORECASE)
_BASIC_AUTH = re.compile(r"https?://[^/\s:]+:[^/\s@]+@")
_PWD_PARAM = re.compile(r"(?:password|pwd)=", re.IGNORECASE)


def _provider_match(value: str) -> tuple[str, str] | None:
    for label, rx in _PROVIDERS:
        m = rx.search(value)
        if m:
            return label, m.group(0)
    return None


def check_mcps020(target: ScanTarget) -> list[Finding]:
    out = []
    for s, key, val in iter_env(target):
        hit = _provider_match(val)
        if hit:
            label, matched = hit
            out.append(finding("MCPS020",
                f"{label} API key exposed in env '{key}' of server '{s.name}'",
                Location(server=s.name, field=f"env.{key}", snippet=mask_secret(matched))))
    # also scan args
    for srv in target.servers:
        for i, a in enumerate(srv.args):
            hit = _provider_match(str(a))
            if hit:
                label, matched = hit
                out.append(finding("MCPS020",
                    f"{label} API key exposed in args of server '{srv.name}'",
                    Location(server=srv.name, field=f"args[{i}]", snippet=mask_secret(matched))))
    return out


def check_mcps021(target: ScanTarget) -> list[Finding]:
    out = []
    for s, key, val in iter_env(target):
        if _provider_match(val):
            continue  # already reported as a known-format key (MCPS020)
        if len(val) >= 20 and _SECRET_NAME.search(key) and shannon_entropy(val) >= 4.0:
            out.append(finding("MCPS021",
                f"high-entropy secret-like value in env '{key}' of server '{s.name}'",
                Location(server=s.name, field=f"env.{key}", snippet=mask_secret(val))))
    return out


def check_mcps022(target: ScanTarget) -> list[Finding]:
    out = []
    for s in target.servers:
        candidates = [("url", s.url or "")] + [(f"args[{i}]", str(a)) for i, a in enumerate(s.args)]
        for field, text in candidates:
            if _BASIC_AUTH.search(text) or _PWD_PARAM.search(text):
                out.append(finding("MCPS022",
                    f"plaintext credential embedded in {field} of server '{s.name}'",
                    Location(server=s.name, field=field, snippet="<inline credential masked>")))
    return out


CHECKS = {
    "MCPS020": check_mcps020,
    "MCPS021": check_mcps021,
    "MCPS022": check_mcps022,
}
