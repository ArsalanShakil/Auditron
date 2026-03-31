"""Enforcer — makes and applies final decisions based on Verdict."""

from __future__ import annotations

from agentauditor.core.models import (
    Action,
    Decision,
    PolicyConfig,
    RiskLevel,
    Verdict,
)
from agentauditor.layers.output_layer import redact_text


class Enforcer:
    """Applies enforcement logic: decision precedence, PII redaction, LLM overrides,
    max_risk_level caps."""

    def __init__(self, policy: PolicyConfig) -> None:
        self.policy = policy

    async def enforce(self, verdict: Verdict, action: Action) -> Verdict:
        """Apply enforcement logic and return a finalized verdict.

        Decision precedence: BLOCK > ESCALATE > MODIFY > ALLOW.
        MODIFY triggers PII redaction (stored in verdict, not on action).
        LLM judge can downgrade ESCALATE to ALLOW only with very high confidence
        and never for CRITICAL risk.
        max_risk_level from identity policy is enforced.
        """
        final_decision = verdict.decision
        redacted_output = None

        has_block = any(m.decision == Decision.BLOCK for m in verdict.rule_matches)
        has_escalate = any(m.decision == Decision.ESCALATE for m in verdict.rule_matches)
        has_modify = any(m.decision == Decision.MODIFY for m in verdict.rule_matches)

        if has_block:
            final_decision = Decision.BLOCK
        elif has_escalate:
            final_decision = Decision.ESCALATE
            # LLM judge can downgrade ESCALATE, but with strict conditions
            if verdict.llm_judgments:
                has_critical = any(
                    m.risk_level == RiskLevel.CRITICAL for m in verdict.rule_matches
                )
                if not has_critical:
                    all_safe = all(
                        j.risk_level.severity <= 1
                        and j.confidence >= 0.95
                        and j.aligned_with_goal
                        for j in verdict.llm_judgments
                    )
                    if all_safe:
                        final_decision = Decision.ALLOW
        elif has_modify:
            final_decision = Decision.MODIFY
            # Store redacted output in verdict (don't mutate action)
            if action.raw_output:
                redacted_output = redact_text(action.raw_output)
        else:
            final_decision = self.policy.default_decision

        # Enforce max_risk_level from identity policy
        if action.agent_id and verdict.rule_matches:
            for identity in self.policy.identity_policies:
                if identity.agent_id == action.agent_id or identity.agent_id == "default":
                    if verdict.risk_level > identity.max_risk_level:
                        final_decision = Decision.BLOCK
                    break

        return Verdict(
            action_id=verdict.action_id,
            decision=final_decision,
            risk_level=verdict.risk_level,
            rule_matches=verdict.rule_matches,
            llm_judgments=verdict.llm_judgments,
            explanation=verdict.explanation,
            layer=verdict.layer,
            latency_ms=verdict.latency_ms,
            redacted_output=redacted_output,
            timestamp=verdict.timestamp,
        )
