"""Tests for core data models."""

from agentauditor.core.models import (
    Action,
    ActionType,
    AgentIdentity,
    Decision,
    DefenseLayer,
    LLMJudgment,
    PatternMatch,
    PolicyConfig,
    PolicyRule,
    RiskLevel,
    RuleMatch,
    Verdict,
)


class TestRiskLevel:
    def test_severity_ordering(self):
        assert RiskLevel.CRITICAL > RiskLevel.HIGH
        assert RiskLevel.HIGH > RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM > RiskLevel.LOW
        assert RiskLevel.LOW > RiskLevel.INFO

    def test_severity_values(self):
        assert RiskLevel.CRITICAL.severity == 4
        assert RiskLevel.INFO.severity == 0

    def test_comparison(self):
        assert RiskLevel.CRITICAL >= RiskLevel.HIGH
        assert RiskLevel.LOW <= RiskLevel.MEDIUM
        assert not RiskLevel.LOW > RiskLevel.HIGH


class TestDecision:
    def test_priority_ordering(self):
        assert Decision.BLOCK.priority > Decision.ESCALATE.priority
        assert Decision.ESCALATE.priority > Decision.MODIFY.priority
        assert Decision.MODIFY.priority > Decision.ALLOW.priority


class TestAction:
    def test_default_fields(self):
        action = Action(action_type=ActionType.TOOL_CALL)
        assert action.action_id  # UUID generated
        assert action.timestamp
        assert action.parameters == {}
        assert action.agent_id is None

    def test_full_action(self):
        action = Action(
            action_type=ActionType.SHELL_COMMAND,
            tool_name="bash",
            parameters={"command": "ls"},
            raw_input="ls",
            agent_id="agent-1",
        )
        assert action.tool_name == "bash"
        assert action.agent_id == "agent-1"


class TestVerdict:
    def test_serialization(self):
        verdict = Verdict(
            action_id="test-123",
            decision=Decision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            explanation="Blocked dangerous command",
            latency_ms=1.5,
        )
        data = verdict.model_dump(mode="json")
        assert data["decision"] == "block"
        assert data["risk_level"] == "critical"


class TestPolicyConfig:
    def test_defaults(self):
        config = PolicyConfig()
        assert config.default_decision == Decision.ALLOW
        assert config.llm_judge_enabled is False
        assert config.rules == []

    def test_from_dict(self):
        config = PolicyConfig.model_validate({
            "name": "test",
            "rules": [{
                "id": "r1",
                "name": "test_rule",
                "description": "A test rule",
                "layer": "input",
                "risk_level": "high",
            }],
        })
        assert len(config.rules) == 1
        assert config.rules[0].layer == DefenseLayer.INPUT
