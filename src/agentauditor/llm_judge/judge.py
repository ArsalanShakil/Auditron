"""LLM-as-judge orchestration with optional ensemble voting."""

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
from agentauditor.llm_judge.prompts import JUDGE_SYSTEM_PROMPT, JUDGE_USER_TEMPLATE


class BaseLLMProvider(ABC):
    """Abstract LLM provider for judging actions."""

    provider_name: str
    model_name: str

    @abstractmethod
    async def complete(self, system: str, user: str) -> str:
        """Send a completion request and return the raw response text."""
        ...


class LLMJudge:
    """Orchestrates LLM-based evaluation. Only invoked when deterministic
    rules produce risk >= policy threshold."""

    def __init__(
        self, providers: list[BaseLLMProvider], ensemble: bool = False
    ) -> None:
        self.providers = providers
        self.ensemble = ensemble

    async def evaluate(
        self,
        action: Action,
        rule_matches: list[RuleMatch],
        user_goal: str | None = None,
    ) -> list[LLMJudgment]:
        """Query one or more LLM providers. If ensemble=True, query all
        providers in parallel."""
        if not self.providers:
            return []

        user_prompt = self._build_user_prompt(action, rule_matches, user_goal)

        if self.ensemble:
            tasks = [
                self._query_single(provider, user_prompt)
                for provider in self.providers
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [r for r in results if isinstance(r, LLMJudgment)]
        else:
            result = await self._query_single(self.providers[0], user_prompt)
            return [result] if isinstance(result, LLMJudgment) else []

    async def _query_single(
        self, provider: BaseLLMProvider, user_prompt: str
    ) -> LLMJudgment:
        """Query a single provider and parse the response."""
        start = time.monotonic()
        raw_response = await provider.complete(JUDGE_SYSTEM_PROMPT, user_prompt)
        elapsed_ms = (time.monotonic() - start) * 1000

        parsed = self._parse_response(raw_response)

        return LLMJudgment(
            provider=provider.provider_name,
            model=provider.model_name,
            risk_level=RiskLevel(parsed.get("risk_level", "medium")),
            reasoning=parsed.get("reasoning", "Unable to parse response"),
            aligned_with_goal=parsed.get("aligned_with_goal", False),
            confidence=float(parsed.get("confidence", 0.5)),
            latency_ms=elapsed_ms,
        )

    @staticmethod
    def _build_user_prompt(
        action: Action,
        rule_matches: list[RuleMatch],
        user_goal: str | None,
    ) -> str:
        rule_text = "None" if not rule_matches else "\n".join(
            f"- [{m.risk_level.value}] {m.rule_name}: {m.description}"
            for m in rule_matches
        )
        return JUDGE_USER_TEMPLATE.format(
            user_goal=user_goal or "Not specified",
            action_type=action.action_type.value,
            tool_name=action.tool_name or "N/A",
            parameters=json.dumps(action.parameters, default=str),
            raw_input=action.raw_input or "N/A",
            rule_matches=rule_text,
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
                "risk_level": "medium",
                "reasoning": f"Failed to parse LLM response: {raw[:200]}",
                "aligned_with_goal": False,
                "confidence": 0.3,
            }
