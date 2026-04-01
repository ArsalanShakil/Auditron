"""Layer 1: Input — Prompt injection detection with heuristic scoring."""

from __future__ import annotations

import math
from collections import Counter

from agentauditor.core.models import (
    Action,
    ActionType,
    Decision,
    DefenseLayer,
    PolicyConfig,
    RiskLevel,
    RuleMatch,
)
from agentauditor.core.normalizer import TextNormalizer
from agentauditor.layers.base import BaseLayer

# Keywords associated with prompt injection attempts (expanded)
_INJECTION_KEYWORDS = [
    "ignore", "disregard", "forget", "override", "bypass",
    "system prompt", "new instructions", "admin mode", "developer mode",
    "jailbreak", "DAN", "no restrictions", "unrestricted",
    "pretend", "roleplay as", "act as if",
    "no limits", "sudo mode", "god mode", "master prompt",
    "base prompt", "original instructions", "reveal your prompt",
    "show your instructions", "what are your rules",
    "system message", "do anything", "without limitations",
]

# Instruction override markers (expanded)
_MARKERS = [
    "###", "---", "```", "<|", "|>",
    "[INST]", "[/INST]", "[SYSTEM]", "[/SYSTEM]",
    "<<SYS>>", "<</SYS>>",
    "<|im_start|>", "<|im_end|>", "<|endoftext|>",
    "Human:", "Assistant:",
    "INSTRUCTION:", "CONTEXT:",
]


class InputLayer(BaseLayer):
    """Detects prompt injection via rule matches + heuristic entropy/keyword scoring."""

    layer = DefenseLayer.INPUT

    def __init__(self) -> None:
        self._normalizer = TextNormalizer()

    async def analyze(
        self, action: Action, policy: PolicyConfig, rule_matches: list[RuleMatch]
    ) -> list[RuleMatch]:
        if action.action_type != ActionType.PROMPT or not action.raw_input:
            return []

        # If rules already matched, skip heuristics
        if rule_matches:
            return []

        # Normalize before scoring to defeat homoglyph and encoding evasion
        normalized = self._normalizer.normalize(action.raw_input)
        text = normalized.normalized

        score = self._injection_score(text)

        if score >= 0.5:
            description = f"Heuristic prompt injection score: {score:.2f}"
            if normalized.flags:
                description += f" (evasion flags: {', '.join(sorted(normalized.flags))})"
            return [
                RuleMatch(
                    rule_id="input-heuristic",
                    rule_name="heuristic_injection_score",
                    layer=DefenseLayer.INPUT,
                    risk_level=RiskLevel.HIGH,
                    description=description,
                    decision=Decision.ESCALATE,
                    matched_pattern=f"score={score:.2f}",
                    confidence=score,
                )
            ]

        return []

    def _injection_score(self, text: str) -> float:
        """Compute a 0-1 injection likelihood score based on keyword density,
        character entropy, and instruction markers.

        Keyword density is normalized by text length to resist padding attacks:
        an attacker cannot dilute the score by adding benign text.
        """
        if not text:
            return 0.0

        text_lower = text.lower()
        words = text_lower.split()
        if not words:
            return 0.0

        # Keyword density — normalized to text length to resist padding attacks
        keyword_hits = sum(1 for kw in _INJECTION_KEYWORDS if kw in text_lower)
        text_len = len(text_lower)
        if text_len < 100:
            # Short texts: use absolute count (attacker can't pad much)
            keyword_score = min(keyword_hits / 4.0, 1.0)
        else:
            # Longer texts: density per 100 chars, capped at 1.0
            density = keyword_hits / (text_len / 100.0)
            keyword_score = min(density / 2.0, 1.0)

        # Character entropy — injection payloads often have unusual distributions
        entropy = self._char_entropy(text)
        entropy_score = max(0, min((entropy - 4.5) / 2.0, 1.0))

        # Instruction override markers
        marker_score = 0.0
        marker_hits = sum(1 for m in _MARKERS if m in text)
        if marker_hits >= 2:
            marker_score = 0.5
        elif marker_hits == 1:
            marker_score = 0.3

        return min(
            keyword_score * 0.6 + entropy_score * 0.15 + marker_score * 0.25,
            1.0,
        )

    @staticmethod
    def _char_entropy(text: str) -> float:
        """Shannon entropy of character distribution."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())
