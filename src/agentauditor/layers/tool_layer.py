"""Layer 3: Tool Selection — Tool and parameter validation against identity policies."""

from __future__ import annotations

from agentauditor.core.models import (
    Action,
    ActionType,
    Decision,
    DefenseLayer,
    PolicyConfig,
    RiskLevel,
    RuleMatch,
)
from agentauditor.core.normalizer import normalize_tool_name
from agentauditor.layers.base import BaseLayer


class ToolLayer(BaseLayer):
    """Validates tool selection against identity allow/deny lists and parameter constraints."""

    layer = DefenseLayer.TOOL_SELECTION

    async def analyze(
        self, action: Action, policy: PolicyConfig, rule_matches: list[RuleMatch]
    ) -> list[RuleMatch]:
        if action.action_type not in (
            ActionType.TOOL_CALL,
            ActionType.SHELL_COMMAND,
            ActionType.FILE_ACCESS,
            ActionType.API_CALL,
        ):
            return []

        additional: list[RuleMatch] = []

        # Check identity-based tool restrictions (with normalized names)
        if action.agent_id and action.tool_name:
            norm_tool = normalize_tool_name(action.tool_name)
            for identity in policy.identity_policies:
                if identity.agent_id == action.agent_id or identity.agent_id == "default":
                    # Check denied tools (normalized comparison)
                    norm_denied = {normalize_tool_name(t) for t in identity.denied_tools}
                    if norm_denied and norm_tool in norm_denied:
                        additional.append(
                            RuleMatch(
                                rule_id="tool-identity-denied",
                                rule_name="tool_denied_by_identity",
                                layer=DefenseLayer.TOOL_SELECTION,
                                risk_level=RiskLevel.HIGH,
                                description=(
                                    f"Tool '{action.tool_name}' is denied for agent "
                                    f"'{action.agent_id}'"
                                ),
                                decision=Decision.BLOCK,
                                matched_pattern=f"denied:{action.tool_name}",
                            )
                        )

                    # Check allowed tools (normalized comparison)
                    if identity.allowed_tools:
                        norm_allowed = {normalize_tool_name(t) for t in identity.allowed_tools}
                        if norm_tool not in norm_allowed:
                            additional.append(
                                RuleMatch(
                                    rule_id="tool-identity-not-allowed",
                                    rule_name="tool_not_in_allowlist",
                                    layer=DefenseLayer.TOOL_SELECTION,
                                    risk_level=RiskLevel.MEDIUM,
                                    description=(
                                        f"Tool '{action.tool_name}' is not in allowlist for "
                                        f"agent '{action.agent_id}'"
                                    ),
                                    decision=Decision.ESCALATE,
                                    matched_pattern=f"not_allowed:{action.tool_name}",
                                )
                            )
                    break

        return additional
