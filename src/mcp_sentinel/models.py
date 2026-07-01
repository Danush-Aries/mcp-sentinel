"""Shared data contract for mcp-sentinel.

Every module — parsers, rules, report, engine, cli — codes against these types.
Kept dependency-free (stdlib only) so it is the stable center of the package.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Literal

from . import __version__
from .severity import Severity

Category = Literal["poisoning", "capability", "secret", "supplychain", "scope"]


@dataclass(frozen=True)
class ToolSpec:
    """A single MCP tool as the model sees it. `description` is the field most
    abused for poisoning — its text is injected verbatim into the LLM context."""
    name: str
    description: str = ""
    parameters: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ServerSpec:
    """A normalized MCP server, regardless of source client shape."""
    name: str
    command: str | None = None      # npx | uvx | node | python | docker ...
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None          # http/sse transports
    declared_purpose: str = ""      # description/summary if present
    tools: list[ToolSpec] = field(default_factory=list)
    source_path: str = ""
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ScanTarget:
    kind: Literal["settings", "manifest", "stdio"]
    path: str
    servers: list[ServerSpec] = field(default_factory=list)


@dataclass(frozen=True)
class Location:
    """Where a finding lives, for reporting. `snippet` is redacted evidence."""
    server: str
    tool: str | None = None
    field: str | None = None        # "description" | "env.API_KEY" | "args[1]"
    snippet: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    message: str
    location: Location
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def with_fingerprint(self) -> "Finding":
        """Return a copy with a stable fingerprint derived from rule + location."""
        if self.fingerprint:
            return self
        loc = self.location
        basis = f"{self.rule_id}|{loc.server}|{loc.tool}|{loc.field}"
        fp = hashlib.sha1(basis.encode()).hexdigest()[:16]
        return replace_finding(self, fingerprint=fp)


def replace_finding(f: Finding, **changes) -> Finding:
    """dataclasses.replace shim kept local so callers need not import dataclasses."""
    from dataclasses import replace
    return replace(f, **changes)


@dataclass(frozen=True)
class Rule:
    """A detection rule. Metadata is data; `check` is a pure function."""
    id: str
    title: str
    severity: Severity
    category: Category
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    check: Callable[[ScanTarget], list[Finding]] | None = None


@dataclass
class Report:
    target: ScanTarget
    findings: list[Finding]
    schema_version: str = "1.0"
    tool_version: str = __version__

    # --- derived properties -------------------------------------------
    @property
    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.label] = out.get(f.severity.label, 0) + 1
        return out

    @property
    def highest_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def exit_code(self, fail_on: Severity = Severity.MEDIUM, strict: bool = False) -> int:
        """0 clean · 1 findings at/above fail_on · 2 CRITICAL (or strict+HIGH) · 3 error(elsewhere)."""
        hi = self.highest_severity
        if hi is None:
            return 0
        if hi >= Severity.CRITICAL or (strict and hi >= Severity.HIGH):
            return 2
        if hi >= fail_on:
            return 1
        return 0
