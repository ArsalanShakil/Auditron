"""LLM-as-judge orchestration with ReAct reasoning and optional reflection."""

from __future__ import annotations

import asyncio
import json
import time
from abc import ABC, abstractmethod
from typing import Any

from agentauditor.core.models import (
    Action,
    LLMJudgment,
    RiskLevel,
    RuleMatch,
)
from agentauditor.llm_judge.prompts import (
    JUDGE_REFLECTION_PROMPT,
    JUDGE_SYSTEM_PROMPT,
    JUDGE_USER_TEMPLATE,
)


class BaseLLMProvider(ABC):
    """Abstract LLM provider for judging actions."""

    provider_name: str
    model_name: str

    @abstractmethod
    async def complete(self, system: str, user: str) -> str:
        """Send a completion request and return the raw response text."""
        ...


class LLMJudge:
    """Orchestrates LLM-based evaluation with ReAct reasoning and optional
    self-critique reflection. Only invoked when deterministic rules produce
    ambiguous results (low Stage 1 confidence or ESCALATE decisions)."""

    def __init__(
        self,
        providers: list[BaseLLMProvider],
        ensemble: bool = False,
        reflection_enabled: bool = False,
        reflection_trigger_decisions: list[str] | None = None,
    ) -> None:
        self.providers = providers
        self.ensemble = ensemble
        self.reflection_enabled = reflection_enabled
        self.reflection_trigger_decisions = reflection_trigger_decisions or ["escalate"]

    async def evaluate(
        self,
        action: Action,
        rule_matches: list[RuleMatch],
        user_goal: str | None = None,
        stage1_confidence: float = 1.0,
        stage1_decision: str = "",
    ) -> list[LLMJudgment]:
        """Query one or more LLM providers with ReAct-structured reasoning.
        If ensemble=True, query all providers in parallel."""
        if not self.providers:
            return []

        user_prompt = self._build_user_prompt(
            action, rule_matches, user_goal, stage1_confidence, stage1_decision
        )

        if self.ensemble:
            tasks = [
                self._query_single(provider, user_prompt, stage1_decision)
                for provider in self.providers
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            judgments = [r for r in results if isinstance(r, LLMJudgment)]
        else:
            try:
                result = await self._query_single(
                    self.providers[0], user_prompt, stage1_decision
                )
                judgments = [result] if isinstance(result, LLMJudgment) else []
            except Exception:
                judgments = []

        # If all providers failed, return a fail-safe escalating judgment
        if not judgments:
            judgments = [
                LLMJudgment(
                    provider="failsafe",
                    model="none",
                    risk_level=RiskLevel.HIGH,
                    reasoning="All LLM judge providers failed or returned no results; defaulting to escalate",
                    aligned_with_goal=False,
                    confidence=0.0,
                    latency_ms=0.0,
                )
            ]
        return judgments

    async def _query_single(
        self,
        provider: BaseLLMProvider,
        user_prompt: str,
        stage1_decision: str = "",
    ) -> LLMJudgment:
        """Query a single provider, parse ReAct response, optionally reflect."""
        start = time.monotonic()
        raw_response = await provider.complete(JUDGE_SYSTEM_PROMPT, user_prompt)
        elapsed_ms = (time.monotonic() - start) * 1000

        parsed = self._parse_response(raw_response)

        judgment = LLMJudgment(
            provider=provider.provider_name,
            model=provider.model_name,
            risk_level=RiskLevel(parsed.get("risk_level", "medium")),
            reasoning=parsed.get("reasoning", "Unable to parse response"),
            aligned_with_goal=parsed.get("aligned_with_goal", False),
            confidence=float(parsed.get("confidence", 0.5)),
            latency_ms=elapsed_ms,
            thought=parsed.get("thought", ""),
            observation=parsed.get("observation", ""),
            false_positive_likelihood=parsed.get("false_positive_likelihood", "medium"),
            mitigating_factors=parsed.get("mitigating_factors", []),
            aggravating_factors=parsed.get("aggravating_factors", []),
        )

        # Reflection: self-critique for high-stakes decisions
        if (
            self.reflection_enabled
            and stage1_decision in self.reflection_trigger_decisions
        ):
            judgment = await self._reflect_on_judgment(provider, judgment)

        return judgment

    async def _reflect_on_judgment(
        self, provider: BaseLLMProvider, initial: LLMJudgment
    ) -> LLMJudgment:
        """Run a self-critique reflection pass on the initial judgment."""
        initial_summary = json.dumps(
            {
                "risk_level": initial.risk_level.value,
                "reasoning": initial.reasoning,
                "confidence": initial.confidence,
                "false_positive_likelihood": initial.false_positive_likelihood,
                "mitigating_factors": initial.mitigating_factors,
                "aggravating_factors": initial.aggravating_factors,
            },
            indent=2,
        )

        reflection_prompt = JUDGE_REFLECTION_PROMPT.format(
            initial_judgment=initial_summary
        )

        start = time.monotonic()
        try:
            raw = await provider.complete(JUDGE_SYSTEM_PROMPT, reflection_prompt)
            reflection_ms = (time.monotonic() - start) * 1000
        except Exception:
            return initial

        parsed = self._parse_response(raw)
        self_critique = parsed.get("self_critique", "")
        assessment_changed = parsed.get("assessment_changed", False)

        revised = initial.model_copy()
        revised.self_critique = self_critique
        revised.latency_ms += reflection_ms

        if assessment_changed:
            revised_confidence = float(parsed.get("revised_confidence", initial.confidence))
            # Only apply revision if confidence shift is significant (>0.15)
            if abs(revised_confidence - initial.confidence) > 0.15:
                revised.risk_level = RiskLevel(
                    parsed.get("revised_risk_level", initial.risk_level.value)
                )
                revised.confidence = revised_confidence
                revised.assessment_revised = True

        return revised

    @staticmethod
    def _build_user_prompt(
        action: Action,
        rule_matches: list[RuleMatch],
        user_goal: str | None,
        stage1_confidence: float = 1.0,
        stage1_decision: str = "",
    ) -> str:
        rule_text = "None" if not rule_matches else "\n".join(
            f"- [{m.risk_level.value}] {m.rule_name}: {m.description} (confidence: {m.confidence:.2f})"
            for m in rule_matches
        )
        return JUDGE_USER_TEMPLATE.format(
            user_goal=user_goal or "Not specified",
            action_type=action.action_type.value,
            tool_name=action.tool_name or "N/A",
            parameters=json.dumps(action.parameters, default=str),
            raw_input=action.raw_input or "N/A",
            rule_matches=rule_text,
            stage1_confidence=stage1_confidence,
            stage1_decision=stage1_decision or "N/A",
        )

    @staticmethod
    def _parse_response(raw: str) -> dict[str, Any]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
            text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "risk_level": "high",
                "reasoning": f"Failed to parse LLM response: {raw[:200]}",
                "aligned_with_goal": False,
                "confidence": 0.1,
            }
