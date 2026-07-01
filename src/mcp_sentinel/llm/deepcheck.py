"""Optional LLM deep-check (opt-in, off by default).

When explicitly enabled AND an API key is present, this would send ONLY tool
description strings (never env/secrets) to a classifier model to catch paraphrased
prompt injection that the static heuristics miss. In v0.1.0 it is a safe no-op that
returns no findings unless enabled, keeping every default run fully offline.
"""
from __future__ import annotations

import os

from ..models import Finding, ScanTarget

_KEY_ENVS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")


def deep_check(target: ScanTarget, model: str | None = None,
               enabled: bool = False) -> list[Finding]:
    if not enabled:
        return []
    if not any(os.getenv(k) for k in _KEY_ENVS):
        return []
    # Reserved for P3: call the model with tool-description text only.
    # Intentionally a no-op in v0.1.0 so behaviour is deterministic and offline-safe.
    return []
