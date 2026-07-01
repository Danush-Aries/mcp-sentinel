"""Shared pytest fixtures. `src/` is on sys.path via pyproject `pythonpath`."""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def fx():
    """Return a callable mapping a fixture filename -> absolute path string."""
    def _fx(name: str) -> str:
        return str(FIXTURES / name)
    return _fx
