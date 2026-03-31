"""Tests for the LLM judge (with mocked providers)."""

import json

import pytest

from agentauditor.core.models import (
    Action,
    ActionType,
    LLMJudgment,
    RiskLevel,
    RuleMatch,
    DefenseLayer,
)
from agentauditor.llm_judge.judge import BaseLLMProvider, LLMJudge


class MockProvider(BaseLLMProvider):
    """Mock provider that returns a fixed response."""

    provider_name = "mock"
    model_name = "mock-v1"

    def __init__(self, response: dict):
        self._response = response

    async def complete(self, system: str, user: str) -> str:
        return json.dumps(self._response)


class MockBadProvider(BaseLLMProvider):
    """Mock provider that returns invalid JSON."""

    provider_name = "mock-bad"
    model_name = "mock-bad-v1"

    async def complete(self, system: str, user: str) -> str:
        return "This is not JSON at all"


@pytest.mark.asyncio
class TestLLMJudge:
    async def test_single_provider(self):
        provider = MockProvider({
            "risk_level": "high",
            "reasoning": "This looks dangerous",
            "aligned_with_goal": False,
            "confidence": 0.9,
        })
        judge = LLMJudge([provider])
        action = Action(
            action_type=ActionType.SHELL_COMMAND,
            tool_name="bash",
            parameters={"command": "rm -rf /"},
        )
        results = await judge.evaluate(action, [])
        assert len(results) == 1
        assert results[0].risk_level == RiskLevel.HIGH
        assert results[0].confidence == 0.9

    async def test_ensemble_voting(self):
        providers = [
            MockProvider({"risk_level": "high", "reasoning": "bad", "aligned_with_goal": False, "confidence": 0.9}),
            MockProvider({"risk_level": "low", "reasoning": "ok", "aligned_with_goal": True, "confidence": 0.8}),
        ]
        judge = LLMJudge(providers, ensemble=True)
        action = Action(action_type=ActionType.TOOL_CALL, tool_name="test")
        results = await judge.evaluate(action, [])
        assert len(results) == 2

    async def test_handles_bad_json(self):
        judge = LLMJudge([MockBadProvider()])
        action = Action(action_type=ActionType.TOOL_CALL, tool_name="test")
        results = await judge.evaluate(action, [])
        assert len(results) == 1
        assert results[0].risk_level == RiskLevel.MEDIUM  # Fallback
        assert results[0].confidence == 0.3

    async def test_no_providers(self):
        judge = LLMJudge([])
        action = Action(action_type=ActionType.TOOL_CALL, tool_name="test")
        results = await judge.evaluate(action, [])
        assert len(results) == 0

    async def test_with_user_goal(self):
        provider = MockProvider({
            "risk_level": "low",
            "reasoning": "Aligned with goal",
            "aligned_with_goal": True,
            "confidence": 0.95,
        })
        judge = LLMJudge([provider])
        action = Action(
            action_type=ActionType.TOOL_CALL,
            tool_name="read_file",
            parameters={"path": "/tmp/data.txt"},
        )
        results = await judge.evaluate(
            action, [], user_goal="Read the data file and summarize it"
        )
        assert len(results) == 1
        assert results[0].aligned_with_goal is True

    async def test_with_rule_matches(self):
        provider = MockProvider({
            "risk_level": "high",
            "reasoning": "Rule matches indicate risk",
            "aligned_with_goal": False,
            "confidence": 0.85,
        })
        judge = LLMJudge([provider])
        action = Action(action_type=ActionType.SHELL_COMMAND, tool_name="bash")
        matches = [
            RuleMatch(
                rule_id="tool-001",
                rule_name="test_rule",
                layer=DefenseLayer.TOOL_SELECTION,
                risk_level=RiskLevel.HIGH,
                description="Test match",
            )
        ]
        results = await judge.evaluate(action, matches)
        assert len(results) == 1
