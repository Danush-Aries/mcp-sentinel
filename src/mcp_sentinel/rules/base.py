"""Shared rule metadata + detection helpers.

`META` is the single runtime source of truth for rule metadata (title, severity,
category, remediation). `rules/data/rules.yaml` mirrors it for humans and the
`rules` CLI command. Category modules import `META` and `finding()` and implement
pure `check_*(target) -> list[Finding]` functions.
"""
from __future__ import annotations

import base64
import math
import re
from collections.abc import Iterator

from ..models import Finding, Location, ScanTarget, ServerSpec, ToolSpec
from ..severity import Severity

# --- rule metadata (source of truth) -------------------------------------
META: dict[str, dict] = {
    "MCPS001": {"title": "Instruction-override phrases in tool description",
                "severity": Severity.HIGH, "category": "poisoning",
                "remediation": "Descriptions must describe, not command. Remove imperative "
                               "meta-instructions aimed at the model."},
    "MCPS002": {"title": "Invisible / control unicode in description",
                "severity": Severity.HIGH, "category": "poisoning",
                "remediation": "Strip zero-width, bidi and tag characters; re-author the "
                               "description in printable UTF-8."},
    "MCPS003": {"title": "Encoded payload blob in description/params",
                "severity": Severity.MEDIUM, "category": "poisoning",
                "remediation": "Tool docs should never carry encoded data; remove the blob."},
    "MCPS004": {"title": "Hidden-channel / exfiltration markers in description",
                "severity": Severity.MEDIUM, "category": "poisoning",
                "remediation": "Remove covert-behaviour language and hardcoded destination URLs."},
    "MCPS010": {"title": "Shell / exec capability", "severity": Severity.HIGH,
                "category": "capability",
                "remediation": "Constrain to an allowlist of commands or sandbox the tool."},
    "MCPS011": {"title": "Arbitrary file write / delete", "severity": Severity.HIGH,
                "category": "capability",
                "remediation": "Scope writes to a fixed workspace; deny path traversal; make opt-in."},
    "MCPS012": {"title": "Unbounded network egress", "severity": Severity.MEDIUM,
                "category": "capability",
                "remediation": "Add a host allowlist to the tool schema; block arbitrary URLs."},
    "MCPS013": {"title": "Credential / secret access tool", "severity": Severity.HIGH,
                "category": "capability",
                "remediation": "Remove direct secret-reading tools; broker via a scoped manager."},
    "MCPS020": {"title": "Known-format API key in env/args", "severity": Severity.CRITICAL,
                "category": "secret",
                "remediation": "Move to an env-var reference / secret store and rotate the key now."},
    "MCPS021": {"title": "High-entropy value in env (generic secret)", "severity": Severity.HIGH,
                "category": "secret",
                "remediation": "Replace the literal with ${ENV_VAR} indirection; never commit secrets."},
    "MCPS022": {"title": "Plaintext password / basic-auth in URL", "severity": Severity.HIGH,
                "category": "secret",
                "remediation": "Use token auth via env; strip inline credentials from URLs."},
    "MCPS030": {"title": "Unpinned npx/uvx package", "severity": Severity.HIGH,
                "category": "supplychain",
                "remediation": "Pin an exact version (and npm integrity hash); avoid floating installs."},
    "MCPS031": {"title": "Floating tag / version range", "severity": Severity.MEDIUM,
                "category": "supplychain",
                "remediation": "Pin to an exact, reviewed released version instead of @latest/ranges."},
    "MCPS032": {"title": "Insecure http:// source", "severity": Severity.HIGH,
                "category": "supplychain",
                "remediation": "Use https://; verify TLS; prefer signed registry sources."},
    "MCPS033": {"title": "Unknown / unscoped publisher", "severity": Severity.LOW,
                "category": "supplychain",
                "remediation": "Prefer scoped/official packages; review source before install."},
    "MCPS040": {"title": "Capability broader than declared purpose", "severity": Severity.MEDIUM,
                "category": "scope",
                "remediation": "A read-only server should not expose exec/write/secret tools."},
    "MCPS041": {"title": "Excess tool count / wildcard scope", "severity": Severity.LOW,
                "category": "scope",
                "remediation": "Reduce to a least-privilege tool set; justify each tool."},
}

REFERENCES = ["https://modelcontextprotocol.io/", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"]


def finding(rule_id: str, message: str, location: Location) -> Finding:
    m = META[rule_id]
    return Finding(rule_id=rule_id, title=m["title"], severity=m["severity"],
                   message=message, location=location, remediation=m["remediation"],
                   references=list(REFERENCES))


# --- iteration helpers ---------------------------------------------------
def iter_tools(target: ScanTarget) -> Iterator[tuple[ServerSpec, ToolSpec]]:
    for s in target.servers:
        for t in s.tools:
            yield s, t


def iter_env(target: ScanTarget) -> Iterator[tuple[ServerSpec, str, str]]:
    for s in target.servers:
        for k, v in s.env.items():
            yield s, k, str(v)


def tool_text(t: ToolSpec) -> str:
    """All model-visible text for a tool: its description + parameter descriptions."""
    parts = [t.description or ""]
    params = t.parameters if isinstance(t.parameters, dict) else {}
    for pv in params.values():
        if isinstance(pv, dict):
            parts.append(str(pv.get("description", "")))
    return "\n".join(p for p in parts if p)


def param_names(t: ToolSpec) -> set[str]:
    params = t.parameters if isinstance(t.parameters, dict) else {}
    return {str(k).lower() for k in params.keys()}


# --- primitive detectors -------------------------------------------------
_INVISIBLE = (
    [0x200B, 0x200C, 0x200D, 0xFEFF]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
    + list(range(0xE0000, 0xE0080))
)
_INVISIBLE_SET = set(_INVISIBLE)

_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def has_invisible_unicode(s: str) -> bool:
    return any(ord(ch) in _INVISIBLE_SET for ch in s)


def find_base64_blob(s: str) -> str | None:
    for m in _B64.finditer(s):
        chunk = m.group(0)
        try:
            base64.b64decode(chunk, validate=True)
        except Exception:
            continue
        return chunk
    return None


def mask_secret(s: str) -> str:
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}…{s[-4:]}"
