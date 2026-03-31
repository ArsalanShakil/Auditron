"""Tests for rate limiting and anomaly detection."""

import time

import pytest

from agentauditor.core.rate_limiter import AnomalyTracker


class TestAnomalyTracker:
    def test_no_lockout_initially(self):
        tracker = AnomalyTracker()
        assert tracker.check_lockout("agent-1") is None

    def test_no_lockout_without_agent_id(self):
        tracker = AnomalyTracker()
        assert tracker.check_lockout(None) is None

    def test_record_does_not_lock_on_allow(self):
        tracker = AnomalyTracker(max_blocks_per_minute=3)
        for _ in range(10):
            tracker.record("agent-1", was_blocked=False)
        assert tracker.check_lockout("agent-1") is None

    def test_lockout_after_max_blocks(self):
        tracker = AnomalyTracker(max_blocks_per_minute=3, lockout_duration_s=10)
        for _ in range(3):
            tracker.record("agent-1", was_blocked=True)
        match = tracker.check_lockout("agent-1")
        assert match is not None
        assert match.rule_id == "rate-lockout"
        assert match.decision.value == "block"

    def test_lockout_does_not_affect_other_agents(self):
        tracker = AnomalyTracker(max_blocks_per_minute=2)
        for _ in range(2):
            tracker.record("agent-bad", was_blocked=True)
        assert tracker.check_lockout("agent-bad") is not None
        assert tracker.check_lockout("agent-good") is None

    def test_rate_limit_check(self):
        tracker = AnomalyTracker(max_actions_per_minute=5)
        for _ in range(5):
            tracker.record("agent-1", was_blocked=False)
        match = tracker.check_rate("agent-1")
        assert match is not None
        assert match.rule_id == "rate-limit"

    def test_rate_limit_not_triggered_below_threshold(self):
        tracker = AnomalyTracker(max_actions_per_minute=10)
        for _ in range(5):
            tracker.record("agent-1", was_blocked=False)
        assert tracker.check_rate("agent-1") is None

    def test_none_agent_id_safe(self):
        tracker = AnomalyTracker(max_blocks_per_minute=1)
        tracker.record(None, was_blocked=True)
        tracker.record(None, was_blocked=True)
        assert tracker.check_lockout(None) is None
        assert tracker.check_rate(None) is None
