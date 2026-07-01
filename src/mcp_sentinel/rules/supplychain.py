"""Supply-chain rules (MCPS030–033). Inspect a server's command + args."""
from __future__ import annotations

import re

from ..models import Finding, Location, ScanTarget, ServerSpec
from .base import finding

_PKG_MANAGERS = {"npx", "uvx", "pnpm"}
_KNOWN_SCOPES = {"@modelcontextprotocol", "@anthropic", "@openai"}
_EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+([.\-+][\w.\-]*)?$")
_FLOATING = {"latest", "next", "beta", "canary", "dev", "edge"}
_RANGE_CHARS = set("^~*><= x")


def _package_arg(server: ServerSpec) -> str | None:
    for a in server.args:
        a = str(a)
        if a.startswith("-") or a == "dlx":
            continue
        return a
    return None


def _version_of(pkg: str) -> str | None:
    idx = pkg.rfind("@")
    if idx <= 0:  # no '@', or only the leading scope '@'
        return None
    return pkg[idx + 1:]


def check_mcps030(target: ScanTarget) -> list[Finding]:
    out = []
    for s in target.servers:
        if s.command not in _PKG_MANAGERS:
            continue
        pkg = _package_arg(s)
        if pkg is None:
            continue
        if _version_of(pkg) is None:
            out.append(finding("MCPS030",
                f"server '{s.name}' installs unpinned package '{pkg}' via {s.command}",
                Location(server=s.name, field="args", snippet=pkg)))
    return out


def check_mcps031(target: ScanTarget) -> list[Finding]:
    out = []
    for s in target.servers:
        if s.command not in _PKG_MANAGERS:
            continue
        pkg = _package_arg(s)
        if pkg is None:
            continue
        ver = _version_of(pkg)
        if ver is None:
            continue  # unpinned is MCPS030
        if _EXACT_SEMVER.match(ver):
            continue  # properly pinned
        if ver.lower() in _FLOATING or any(c in _RANGE_CHARS for c in ver):
            out.append(finding("MCPS031",
                f"server '{s.name}' uses a floating version '{ver}' for '{pkg}'",
                Location(server=s.name, field="args", snippet=pkg)))
    return out


def check_mcps032(target: ScanTarget) -> list[Finding]:
    out = []
    for s in target.servers:
        blobs = [s.url or ""] + [str(a) for a in s.args]
        for b in blobs:
            if re.search(r"http://", b, re.IGNORECASE):
                out.append(finding("MCPS032",
                    f"server '{s.name}' references an insecure http:// source",
                    Location(server=s.name, field="args", snippet=b[:60])))
                break
    return out


def check_mcps033(target: ScanTarget) -> list[Finding]:
    out = []
    for s in target.servers:
        if s.command not in _PKG_MANAGERS:
            continue
        pkg = _package_arg(s)
        if pkg is None:
            continue
        scope = pkg.split("/")[0] if pkg.startswith("@") else None
        if scope in _KNOWN_SCOPES:
            continue
        why = "unscoped package" if scope is None else f"unrecognized publisher {scope}"
        out.append(finding("MCPS033",
            f"server '{s.name}' installs '{pkg}' from an {why}",
            Location(server=s.name, field="args", snippet=pkg)))
    return out


CHECKS = {
    "MCPS030": check_mcps030,
    "MCPS031": check_mcps031,
    "MCPS032": check_mcps032,
    "MCPS033": check_mcps033,
}
