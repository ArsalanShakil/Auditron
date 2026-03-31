"""Tests for the tool selection defense layer."""

import pytest

from agentauditor.core.models import (
    Action,
    ActionType,
    AgentIdentity,
    Decision,
    PolicyConfig,
)
from agentauditor.layers.tool_layer import ToolLayer
from agentauditor.policies.loader import load_policy


@pytest.mark.asyncio
class TestToolLayer:
    async def test_blocks_denied_tool(self):
        layer = ToolLayer()
        policy = PolicyConfig(
            identity_policies=[
                AgentIdentity(
                    agent_id="agent-1",
                    name="Test",
                    denied_tools=["bash"],
                )
            ]
        )
        action = Action(
            action_type=ActionType.TOOL_CALL,
            tool_name="bash",
            agent_id="agent-1",
        )
        matches = await layer.analyze(action, policy, [])
        assert len(matches) >= 1
        assert matches[0].decision == Decision.BLOCK

    async def test_escalates_non_allowed_tool(self):
        layer = ToolLayer()
        policy = PolicyConfig(
            identity_policies=[
                AgentIdentity(
                    agent_id="agent-1",
                    name="Test",
                    allowed_tools=["read_file"],
                )
            ]
        )
        action = Action(
            action_type=ActionType.TOOL_CALL,
            tool_name="write_file",
            agent_id="agent-1",
        )
        matches = await layer.analyze(action, policy, [])
        assert len(matches) >= 1
        assert matches[0].decision == Decision.ESCALATE

    async def test_allows_permitted_tool(self):
        layer = ToolLayer()
        policy = PolicyConfig(
            identity_policies=[
                AgentIdentity(
                    agent_id="agent-1",
                    name="Test",
                    allowed_tools=["read_file"],
                )
            ]
        )
        action = Action(
            action_type=ActionType.TOOL_CALL,
            tool_name="read_file",
            agent_id="agent-1",
        )
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0

    async def test_skips_non_tool_actions(self):
        layer = ToolLayer()
        policy = load_policy()
        action = Action(action_type=ActionType.PROMPT, raw_input="hello")
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0
