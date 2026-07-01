"""Rule registry. `ALL_RULES` binds each rule's metadata (from base.META) to its
pure check function; `load_rules` applies select/ignore filters."""
from __future__ import annotations

from ..models import Rule
from . import capabilities, poisoning, scope, secrets, supplychain
from .base import META, REFERENCES

_CHECK_REGISTRY: dict = {}
for _mod in (poisoning, capabilities, secrets, supplychain, scope):
    _CHECK_REGISTRY.update(_mod.CHECKS)

ALL_RULES: list[Rule] = [
    Rule(id=rid, title=m["title"], severity=m["severity"], category=m["category"],
         remediation=m["remediation"], references=list(REFERENCES),
         check=_CHECK_REGISTRY.get(rid))
    for rid, m in META.items()
]

__all__ = ["ALL_RULES", "load_rules"]


def load_rules(select: list[str] | None = None,
               ignore: list[str] | None = None) -> list[Rule]:
    rules = ALL_RULES
    if select:
        sel = {s.upper() for s in select}
        rules = [r for r in rules if r.id in sel]
    if ignore:
        ig = {s.upper() for s in ignore}
        rules = [r for r in rules if r.id not in ig]
    return rules
