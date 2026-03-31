"""Layer 8: Identity — Permission enforcement and agent registration checks."""

from __future__ import annotations

from agentauditor.core.identity import AgentRegistry
from agentauditor.core.models import (
    Action,
    Decision,
    DefenseLayer,
    PolicyConfig,
    RiskLevel,
    RuleMatch,
)
from agentauditor.layers.base import BaseLayer


class IdentityLayer(BaseLayer):
    """Enforces identity-based access control for agents."""

    layer = DefenseLayer.IDENTITY

    def __init__(self) -> None:
        self._registry = AgentRegistry()

    def register_agent(
        self, agent_id: str, permissions: set[str] | None = None, secret: str | None = None
    ) -> str | None:
        """Register an agent. Returns token if secret provided."""
        try:
            return self._registry.register(agent_id, permissions, secret)
        except ValueError:
            # Already registered — update instead (backward compat)
            return self._registry.update(agent_id, permissions)

    def is_registered(self, agent_id: str) -> bool:
        return self._registry.is_registered(agent_id)

    @property
    def registry(self) -> AgentRegistry:
        return self._registry

    async def analyze(
        self, action: Action, policy: PolicyConfig, rule_matches: list[RuleMatch]
    ) -> list[RuleMatch]:
        additional: list[RuleMatch] = []

        if not action.agent_id:
            return []

        # Check if agent is registered
        if not self.is_registered(action.agent_id):
            has_identity_rule = any(
                r.layer == DefenseLayer.IDENTITY and r.enabled for r in policy.rules
            )
            if has_identity_rule:
                additional.append(
                    RuleMatch(
                        rule_id="identity-unregistered",
                        rule_name="unregistered_agent_detected",
                        layer=DefenseLayer.IDENTITY,
                        risk_level=RiskLevel.MEDIUM,
                        description=f"Agent '{action.agent_id}' is not registered",
                        decision=Decision.ESCALATE,
                        matched_pattern=f"unregistered:{action.agent_id}",
                    )
                )
        else:
            # Verify token if agent was registered with one
            auth_token = action.context.get("auth_token")
            if not self._registry.verify(action.agent_id, auth_token):
                additional.append(
                    RuleMatch(
                        rule_id="identity-invalid-token",
                        rule_name="invalid_agent_token",
                        layer=DefenseLayer.IDENTITY,
                        risk_level=RiskLevel.CRITICAL,
                        description=f"Invalid authentication token for agent '{action.agent_id}'",
                        decision=Decision.BLOCK,
                        matched_pattern=f"invalid_token:{action.agent_id}",
                    )
                )

        return additional
