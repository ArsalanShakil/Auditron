"""Shared fixtures for benchmark tests."""

import pytest

from agentauditor.core.engine import AuditEngine


@pytest.fixture
def engine() -> AuditEngine:
    return AuditEngine()
