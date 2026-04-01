"""Tests for audit storage backends."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentauditor.logging.backends.memory import InMemoryBackend
from agentauditor.logging.backends.sqlite import SQLiteBackend
from agentauditor.logging.backends.jsonl import JSONLBackend


def _make_entry(
    agent_id: str = "test-agent",
    decision: str = "block",
    risk_level: str = "high",
    action_id: str = "test-1",
) -> dict:
    return {
        "action_id": action_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_type": "shell_command",
        "tool_name": "bash",
        "agent_id": agent_id,
        "decision": decision,
        "risk_level": risk_level,
        "explanation": "Test entry",
        "rule_matches": [{"rule_id": "test-001", "rule_name": "test"}],
        "latency_ms": 0.5,
    }


class TestInMemoryBackend:
    def test_store_and_query(self):
        backend = InMemoryBackend()
        backend.store(_make_entry())
        results = backend.query()
        assert len(results) == 1
        assert results[0]["agent_id"] == "test-agent"

    def test_query_filter_agent_id(self):
        backend = InMemoryBackend()
        backend.store(_make_entry(agent_id="agent-a"))
        backend.store(_make_entry(agent_id="agent-b"))
        results = backend.query(agent_id="agent-a")
        assert len(results) == 1

    def test_query_filter_decision(self):
        backend = InMemoryBackend()
        backend.store(_make_entry(decision="block"))
        backend.store(_make_entry(decision="allow"))
        results = backend.query(decision="block")
        assert len(results) == 1

    def test_count(self):
        backend = InMemoryBackend()
        for _ in range(5):
            backend.store(_make_entry())
        assert backend.count() == 5

    def test_max_size_eviction(self):
        backend = InMemoryBackend(max_size=3)
        for i in range(5):
            backend.store(_make_entry(action_id=f"action-{i}"))
        assert backend.count() == 3

    def test_limit_and_offset(self):
        backend = InMemoryBackend()
        for i in range(10):
            backend.store(_make_entry(action_id=f"action-{i}"))
        results = backend.query(limit=3, offset=2)
        assert len(results) == 3


class TestSQLiteBackend:
    def test_store_and_query(self, tmp_path):
        db = tmp_path / "test.db"
        backend = SQLiteBackend(db_path=db)
        backend.store(_make_entry())
        results = backend.query()
        assert len(results) == 1
        assert results[0]["agent_id"] == "test-agent"
        backend.close()

    def test_query_filter_agent_id(self, tmp_path):
        backend = SQLiteBackend(db_path=tmp_path / "test.db")
        backend.store(_make_entry(agent_id="agent-a"))
        backend.store(_make_entry(agent_id="agent-b"))
        results = backend.query(agent_id="agent-a")
        assert len(results) == 1
        backend.close()

    def test_query_filter_risk_level(self, tmp_path):
        backend = SQLiteBackend(db_path=tmp_path / "test.db")
        backend.store(_make_entry(risk_level="critical"))
        backend.store(_make_entry(risk_level="low"))
        results = backend.query(risk_level="critical")
        assert len(results) == 1
        backend.close()

    def test_count(self, tmp_path):
        backend = SQLiteBackend(db_path=tmp_path / "test.db")
        for _ in range(5):
            backend.store(_make_entry())
        assert backend.count() == 5
        backend.close()

    def test_persistence(self, tmp_path):
        db = tmp_path / "persist.db"
        backend1 = SQLiteBackend(db_path=db)
        backend1.store(_make_entry())
        backend1.close()

        # Reopen — data should persist
        backend2 = SQLiteBackend(db_path=db)
        assert backend2.count() == 1
        backend2.close()

    def test_rule_matches_json(self, tmp_path):
        backend = SQLiteBackend(db_path=tmp_path / "test.db")
        backend.store(_make_entry())
        results = backend.query()
        assert isinstance(results[0]["rule_matches"], list)
        backend.close()


class TestJSONLBackend:
    def test_store_and_query(self, tmp_path):
        f = tmp_path / "test.jsonl"
        backend = JSONLBackend(file_path=f)
        backend.store(_make_entry())
        results = backend.query()
        assert len(results) == 1

    def test_append_only(self, tmp_path):
        f = tmp_path / "test.jsonl"
        backend = JSONLBackend(file_path=f)
        backend.store(_make_entry(action_id="1"))
        backend.store(_make_entry(action_id="2"))
        assert backend.count() == 2

    def test_query_filter(self, tmp_path):
        f = tmp_path / "test.jsonl"
        backend = JSONLBackend(file_path=f)
        backend.store(_make_entry(agent_id="a"))
        backend.store(_make_entry(agent_id="b"))
        results = backend.query(agent_id="a")
        assert len(results) == 1

    def test_empty_file(self, tmp_path):
        f = tmp_path / "nonexistent.jsonl"
        backend = JSONLBackend(file_path=f)
        assert backend.query() == []
        assert backend.count() == 0


class TestEngineWithBackend:
    @pytest.mark.asyncio
    async def test_engine_with_sqlite(self, tmp_path):
        from agentauditor.core.engine import AuditEngine
        from agentauditor.core.models import Decision

        backend = SQLiteBackend(db_path=tmp_path / "engine.db")
        engine = AuditEngine(audit_backend=backend)
        await engine.intercept_tool_call("bash", {"command": "rm -rf /"})
        assert backend.count() == 1
        results = backend.query(decision="block")
        assert len(results) == 1
        backend.close()
