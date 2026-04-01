"""Tests for persistent JSONL audit logging via the backend system."""

import json
import tempfile
from pathlib import Path

import pytest

from agentauditor.core.models import Action, ActionType, Decision, RiskLevel, Verdict
from agentauditor.logging.audit_logger import AuditLogger
from agentauditor.logging.backends.jsonl import JSONLBackend
from agentauditor.logging.backends.memory import InMemoryBackend


def _make_action_and_verdict() -> tuple[Action, Verdict]:
    action = Action(action_type=ActionType.TOOL_CALL, tool_name="bash", agent_id="test-agent")
    verdict = Verdict(
        action_id=action.action_id,
        decision=Decision.BLOCK,
        risk_level=RiskLevel.CRITICAL,
        explanation="Destructive command blocked",
        latency_ms=5.0,
    )
    return action, verdict


class TestAuditLoggerBuffer:
    def test_logs_to_ring_buffer(self):
        logger = AuditLogger()
        action, verdict = _make_action_and_verdict()
        logger.log_verdict(action, verdict)
        assert logger.total_audits == 1
        logs = logger.get_recent_logs()
        assert len(logs) == 1
        assert logs[0]["decision"] == "block"
        assert logs[0]["risk_level"] == "critical"

    def test_get_recent_logs_limit(self):
        logger = AuditLogger(max_buffer_size=100)
        action, verdict = _make_action_and_verdict()
        for _ in range(10):
            logger.log_verdict(action, verdict)
        logs = logger.get_recent_logs(limit=3)
        assert len(logs) == 3

    def test_ring_buffer_evicts_old_entries(self):
        logger = AuditLogger(max_buffer_size=5)
        action, verdict = _make_action_and_verdict()
        for _ in range(10):
            logger.log_verdict(action, verdict)
        assert logger.total_audits == 5  # Ring buffer capped at 5


class TestAuditLoggerJSONL:
    def test_writes_jsonl_file(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            log_path = Path(f.name)

        try:
            backend = JSONLBackend(file_path=log_path)
            logger = AuditLogger(backend=backend)
            action, verdict = _make_action_and_verdict()
            logger.log_verdict(action, verdict)

            lines = log_path.read_text(encoding="utf-8").splitlines()
            assert len(lines) == 1

            entry = json.loads(lines[0])
            assert entry["decision"] == "block"
            assert entry["risk_level"] == "critical"
            assert entry["tool_name"] == "bash"
            assert entry["agent_id"] == "test-agent"
        finally:
            log_path.unlink(missing_ok=True)

    def test_appends_multiple_verdicts(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            log_path = Path(f.name)

        try:
            backend = JSONLBackend(file_path=log_path)
            logger = AuditLogger(backend=backend)
            action, verdict = _make_action_and_verdict()
            logger.log_verdict(action, verdict)
            logger.log_verdict(action, verdict)
            logger.log_verdict(action, verdict)

            lines = log_path.read_text(encoding="utf-8").splitlines()
            assert len(lines) == 3
            for line in lines:
                parsed = json.loads(line)
                assert parsed["decision"] == "block"
        finally:
            log_path.unlink(missing_ok=True)

    def test_jsonl_entry_has_required_fields(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            log_path = Path(f.name)

        try:
            backend = JSONLBackend(file_path=log_path)
            logger = AuditLogger(backend=backend)
            action, verdict = _make_action_and_verdict()
            logger.log_verdict(action, verdict)

            entry = json.loads(log_path.read_text(encoding="utf-8").strip())
            required_fields = {
                "action_id", "timestamp", "action_type", "tool_name",
                "agent_id", "decision", "risk_level", "explanation",
                "rule_matches", "latency_ms",
            }
            assert required_fields.issubset(entry.keys())
        finally:
            log_path.unlink(missing_ok=True)

    def test_no_file_with_default_memory_backend(self):
        logger = AuditLogger()  # Default InMemoryBackend
        action, verdict = _make_action_and_verdict()
        logger.log_verdict(action, verdict)
        assert logger.total_audits == 1

    def test_backend_query_filters_by_decision(self):
        backend = InMemoryBackend()
        logger = AuditLogger(backend=backend)
        action, verdict = _make_action_and_verdict()
        logger.log_verdict(action, verdict)

        results = backend.query(decision="block")
        assert len(results) == 1
        assert results[0]["decision"] == "block"

        results = backend.query(decision="allow")
        assert len(results) == 0
