"""Streaming token-level interception for real-time output analysis.

Provides windowed analysis of streaming LLM output with early-exit
on high-confidence threat detection.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Callable

from agentauditor.core.models import (
    Action,
    ActionType,
    Decision,
    RiskLevel,
    RuleMatch,
    Verdict,
)
from agentauditor.rules.rule_engine import RuleEngine


class StreamBuffer:
    """Accumulates tokens and triggers analysis at window boundaries."""

    def __init__(
        self,
        window_size: int = 50,
        overlap: int = 10,
        max_buffer: int = 10000,
    ) -> None:
        self.window_size = window_size
        self.overlap = overlap
        self.max_buffer = max_buffer
        self._tokens: list[str] = []
        self._window_start: int = 0

    def add_token(self, token: str) -> bool:
        """Add a token, return True if analysis window is ready."""
        self._tokens.append(token)
        tokens_since_window = len(self._tokens) - self._window_start
        return tokens_since_window >= self.window_size

    @property
    def current_window(self) -> str:
        """Return the current analysis window text."""
        return "".join(self._tokens[self._window_start:])

    @property
    def full_text(self) -> str:
        """Return all accumulated text."""
        return "".join(self._tokens)

    @property
    def token_count(self) -> int:
        return len(self._tokens)

    def advance_window(self) -> None:
        """Advance the window by (window_size - overlap) tokens."""
        advance = max(1, self.window_size - self.overlap)
        self._window_start = min(self._window_start + advance, len(self._tokens))


class StreamAnalyzer:
    """Incremental analysis engine for streaming output."""

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._rule_engine = rule_engine

    def analyze_window(self, window_text: str, full_text: str) -> list[RuleMatch]:
        """Run rule engine on window text. Returns matches."""
        action = Action(
            action_type=ActionType.OUTPUT,
            raw_output=window_text,
        )
        return self._rule_engine.evaluate(action)

    @staticmethod
    def should_early_exit(matches: list[RuleMatch]) -> bool:
        """Return True if matches warrant stopping the stream."""
        return any(
            m.risk_level.severity >= RiskLevel.HIGH.severity
            and m.confidence >= 0.9
            for m in matches
        )


async def scan_stream(
    token_stream: AsyncIterator[str],
    rule_engine: RuleEngine,
    agent_id: str | None = None,
    window_size: int = 50,
    overlap: int = 10,
    on_match: Callable[[list[RuleMatch]], Any] | None = None,
) -> Verdict:
    """Scan a streaming token output for threats.

    Buffers tokens, runs analysis at window boundaries, and returns
    a final verdict. Supports early-exit on high-confidence matches.

    Args:
        token_stream: Async iterator yielding tokens (strings).
        rule_engine: The rule engine to use for analysis.
        agent_id: Optional agent ID for the action.
        window_size: Number of tokens per analysis window.
        overlap: Token overlap between windows.
        on_match: Optional callback when matches are found mid-stream.

    Returns:
        Final Verdict after stream completes or early-exit.
    """
    buffer = StreamBuffer(window_size=window_size, overlap=overlap)
    analyzer = StreamAnalyzer(rule_engine)
    all_matches: list[RuleMatch] = []

    async for token in token_stream:
        window_ready = buffer.add_token(token)

        if window_ready:
            matches = analyzer.analyze_window(buffer.current_window, buffer.full_text)
            if matches:
                all_matches.extend(matches)
                if on_match:
                    on_match(matches)
                if analyzer.should_early_exit(matches):
                    break
            buffer.advance_window()

    # Final analysis on complete text
    if buffer.full_text:
        final_matches = analyzer.analyze_window(buffer.full_text, buffer.full_text)
        for m in final_matches:
            if not any(existing.rule_id == m.rule_id for existing in all_matches):
                all_matches.extend([m])

    if all_matches:
        all_matches.sort(key=lambda m: m.risk_level.severity, reverse=True)
        highest_risk = all_matches[0].risk_level
        highest_decision = max(all_matches, key=lambda m: m.decision.priority).decision
    else:
        highest_risk = RiskLevel.INFO
        highest_decision = Decision.ALLOW

    explanation = (
        f"[{highest_risk.value}] {all_matches[0].description}"
        if all_matches else "No security issues detected in stream."
    )

    return Verdict(
        action_id="stream",
        decision=highest_decision,
        risk_level=highest_risk,
        rule_matches=all_matches,
        explanation=explanation,
        latency_ms=0.0,
    )
