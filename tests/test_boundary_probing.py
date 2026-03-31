"""Tests for boundary probing and loop detection in AnomalyTracker."""

import pytest

from agentauditor.core.models import Action, ActionType
from agentauditor.core.rate_limiter import AnomalyTracker


def _make_action(
    tool_name: str = "bash",
    command: str = "echo hello",
    raw_input: str | None = None,
) -> Action:
    return Action(
        action_type=ActionType.SHELL_COMMAND,
        tool_name=tool_name,
        parameters={"command": command},
        raw_input=raw_input or command,
        agent_id="test-agent",
    )


class TestBoundaryProbing:
    def test_detects_probing_with_variations(self):
        tracker = AnomalyTracker(boundary_probe_threshold=3)

        # Submit 3 blocked actions with same tool but different params
        for i in range(3):
            action = _make_action(command=f"rm -rf /tmp/test{i}")
            tracker.record_detailed("agent-1", action, was_blocked=True)

        result = tracker.check_boundary_probing("agent-1")
        assert result is not None
        assert result.rule_id == "anomaly-boundary-probe"
        assert "boundary" in result.rule_name.lower()

    def test_no_probing_below_threshold(self):
        tracker = AnomalyTracker(boundary_probe_threshold=3)

        # Only 2 variations — below threshold
        for i in range(2):
            action = _make_action(command=f"rm -rf /tmp/test{i}")
            tracker.record_detailed("agent-1", action, was_blocked=True)

        assert tracker.check_boundary_probing("agent-1") is None

    def test_no_probing_if_allowed(self):
        tracker = AnomalyTracker(boundary_probe_threshold=3)

        # Multiple allowed actions don't trigger probing
        for i in range(5):
            action = _make_action(command=f"echo test{i}")
            tracker.record_detailed("agent-1", action, was_blocked=False)

        assert tracker.check_boundary_probing("agent-1") is None

    def test_probing_per_agent(self):
        tracker = AnomalyTracker(boundary_probe_threshold=3)

        # Agent 1 probes
        for i in range(3):
            action = _make_action(command=f"rm -rf /tmp/test{i}")
            tracker.record_detailed("agent-1", action, was_blocked=True)

        # Agent 2 should not be flagged
        assert tracker.check_boundary_probing("agent-2") is None

    def test_none_agent_safe(self):
        tracker = AnomalyTracker()
        assert tracker.check_boundary_probing(None) is None


class TestRepetitionDetection:
    def test_detects_infinite_loop(self):
        tracker = AnomalyTracker(repetition_threshold=5)

        # Submit identical actions 5 times
        action = _make_action(command="echo stuck_in_loop")
        for _ in range(5):
            tracker.record_detailed("agent-1", action, was_blocked=False)

        result = tracker.check_repetition("agent-1")
        assert result is not None
        assert result.rule_id == "anomaly-repetition"
        assert "repetition" in result.rule_name.lower()

    def test_no_repetition_below_threshold(self):
        tracker = AnomalyTracker(repetition_threshold=5)

        action = _make_action(command="echo hello")
        for _ in range(4):
            tracker.record_detailed("agent-1", action, was_blocked=False)

        assert tracker.check_repetition("agent-1") is None

    def test_varied_actions_no_repetition(self):
        tracker = AnomalyTracker(repetition_threshold=5)

        for i in range(10):
            action = _make_action(command=f"echo {i}")
            tracker.record_detailed("agent-1", action, was_blocked=False)

        assert tracker.check_repetition("agent-1") is None

    def test_none_agent_safe(self):
        tracker = AnomalyTracker()
        assert tracker.check_repetition(None) is None


class TestRecordDetailed:
    def test_record_detailed_also_does_rate_limiting(self):
        tracker = AnomalyTracker(max_blocks_per_minute=2, lockout_duration_s=10)

        action = _make_action()
        for _ in range(2):
            tracker.record_detailed("agent-1", action, was_blocked=True)

        # Lockout should be triggered via the legacy record path
        assert tracker.check_lockout("agent-1") is not None

    def test_fingerprints_stored(self):
        tracker = AnomalyTracker()
        action = _make_action(command="echo test")
        tracker.record_detailed("agent-1", action, was_blocked=False)

        assert len(tracker._fingerprints["agent-1"]) == 1
        fp = tracker._fingerprints["agent-1"][0]
        assert fp.tool_name == "bash"
        assert fp.param_hash != ""
        assert fp.was_blocked is False
