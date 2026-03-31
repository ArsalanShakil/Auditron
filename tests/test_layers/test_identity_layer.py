"""Tests for the identity defense layer."""

import pytest

from agentauditor.core.models import Action, ActionType, Decision
from agentauditor.layers.identity_layer import IdentityLayer
from agentauditor.policies.loader import load_policy


@pytest.mark.asyncio
class TestIdentityLayer:
    async def test_flags_unregistered_agent(self):
        layer = IdentityLayer()
        policy = load_policy()
        action = Action(
            action_type=ActionType.TOOL_CALL,
            tool_name="bash",
            agent_id="unknown-agent",
        )
        matches = await layer.analyze(action, policy, [])
        assert len(matches) >= 1
        assert matches[0].decision == Decision.ESCALATE

    async def test_skips_registered_agent(self):
        layer = IdentityLayer()
        layer.register_agent("known-agent", {"read"})
        policy = load_policy()
        action = Action(
            action_type=ActionType.TOOL_CALL,
            tool_name="read_file",
            agent_id="known-agent",
        )
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0

    async def test_skips_no_agent_id(self):
        layer = IdentityLayer()
        policy = load_policy()
        action = Action(action_type=ActionType.TOOL_CALL, tool_name="bash")
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0

    async def test_register_and_check(self):
        layer = IdentityLayer()
        assert not layer.is_registered("agent-1")
        layer.register_agent("agent-1")
        assert layer.is_registered("agent-1")
