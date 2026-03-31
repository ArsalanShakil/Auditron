"""Tests for the execution defense layer."""

import pytest

from agentauditor.core.models import Action, ActionType
from agentauditor.layers.execution_layer import ExecutionLayer
from agentauditor.policies.loader import load_policy


@pytest.mark.asyncio
class TestExecutionLayer:
    async def test_skips_non_code_actions(self):
        layer = ExecutionLayer()
        policy = load_policy()
        action = Action(action_type=ActionType.PROMPT, raw_input="hello")
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0
