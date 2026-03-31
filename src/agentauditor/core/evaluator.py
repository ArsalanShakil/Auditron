"""Evaluator — orchestrates defense layers, rule engine, and optional LLM judge."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from agentauditor.core.models import (
    Action,
    Decision,
    DefenseLayer,
    PolicyConfig,
    RiskLevel,
    RuleMatch,
    Verdict,
)

from agentauditor.layers.base import BaseLayer
from agentauditor.rules.rule_engine import RuleEngine

if TYPE_CHECKING:
    from agentauditor.llm_judge.judge import LLMJudge


class Evaluator:
    """Orchestrates the full evaluation pipeline: layers -> rules -> optional LLM judge."""

    def __init__(
        self,
        policy: PolicyConfig,
        rule_engine: RuleEngine,
        layers: list[BaseLayer],
        llm_judge: LLMJudge | None = None,
    ) -> None:
        self.policy = policy
        self.rule_engine = rule_engine
        self.layers = layers
        self.llm_judge = llm_judge

    async def evaluate(self, action: Action) -> Verdict:
        """Main evaluation entry point.

        1. Run rule engine for each layer's rules (deterministic, fast).
        2. Run all applicable defense layers in parallel (heuristic additions).
        3. Aggregate rule matches, determine highest risk level.
        4. If risk >= llm_judge_threshold and LLM judge is configured, invoke it.
        5. Combine results into a Verdict.
        """
        start = time.monotonic()

        # Step 1: Run deterministic rule engine
        all_matches = self.rule_engine.evaluate(action)

        # Step 2: Run defense layers in parallel for heuristic additions
        layer_tasks = []
        for layer in self.layers:
            # Get rule matches relevant to this layer
            layer_matches = [m for m in all_matches if m.layer == layer.layer]
            layer_tasks.append(layer.analyze(action, self.policy, layer_matches))

        if layer_tasks:
            timeout_s = self.policy.max_latency_ms / 1000.0
            try:
                layer_results = await asyncio.wait_for(
                    asyncio.gather(*layer_tasks, return_exceptions=True),
                    timeout=timeout_s,
                )
                for result in layer_results:
                    if isinstance(result, list):
                        all_matches.extend(result)
                    # Exceptions from individual layers are silently ignored
            except asyncio.TimeoutError:
                all_matches.append(
                    RuleMatch(
                        rule_id="system-timeout",
                        rule_name="evaluation_timeout",
                        layer=DefenseLayer.INPUT,
                        risk_level=RiskLevel.HIGH,
                        description=(
                            f"Evaluation timed out after {self.policy.max_latency_ms}ms"
                        ),
                        decision=Decision.ESCALATE,
                    )
                )

        # Step 3: Determine highest risk and decision
        if all_matches:
            all_matches.sort(key=lambda m: m.risk_level.severity, reverse=True)
            highest_risk = all_matches[0].risk_level
            # Decision precedence: block > escalate > modify > allow
            highest_decision = max(all_matches, key=lambda m: m.decision.priority).decision
            primary_layer = all_matches[0].layer
        else:
            highest_risk = RiskLevel.INFO
            highest_decision = self.policy.default_decision
            primary_layer = None

        # Stage 1 confidence: minimum confidence across all matches
        stage1_confidence = (
            min(m.confidence for m in all_matches) if all_matches else 1.0
        )

        # Step 4: Optional LLM judge (Stage 2) — only when Stage 1 is ambiguous
        llm_judgments = []
        needs_llm = (
            self.llm_judge
            and self.policy.llm_judge_enabled
            and highest_risk >= self.policy.llm_judge_threshold
            and (
                stage1_confidence < self.policy.llm_judge_confidence_threshold
                or highest_decision == Decision.ESCALATE
            )
        )
        if needs_llm:
            user_goal = action.context.get("user_goal")
            llm_judgments = await self.llm_judge.evaluate(
                action,
                all_matches,
                user_goal=user_goal,
                stage1_confidence=stage1_confidence,
                stage1_decision=highest_decision.value,
            )

        elapsed_ms = (time.monotonic() - start) * 1000

        # Step 5: Build verdict
        explanation = self._build_explanation(all_matches, llm_judgments)

        return Verdict(
            action_id=action.action_id,
            decision=highest_decision,
            risk_level=highest_risk,
            rule_matches=all_matches,
            llm_judgments=llm_judgments,
            explanation=explanation,
            layer=primary_layer,
            latency_ms=elapsed_ms,
            stage1_confidence=stage1_confidence,
        )

    @staticmethod
    def _build_explanation(
        matches: list[RuleMatch], llm_judgments: list
    ) -> str:
        if not matches and not llm_judgments:
            return "No security issues detected."

        parts = []
        if matches:
            top = matches[0]
            parts.append(f"[{top.risk_level.value}] {top.description}")
            if len(matches) > 1:
                parts.append(f"({len(matches)} total rule matches)")

        if llm_judgments:
            for j in llm_judgments:
                parts.append(f"LLM judge ({j.provider}): {j.reasoning}")

        return " | ".join(parts)
