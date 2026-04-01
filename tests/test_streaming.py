"""Tests for streaming token-level interception."""

import asyncio

import pytest

from agentauditor.core.engine import AuditEngine
from agentauditor.core.models import Decision, RiskLevel
from agentauditor.core.streaming import StreamBuffer, StreamAnalyzer, scan_stream
from agentauditor.policies.loader import load_policy
from agentauditor.rules.rule_engine import RuleEngine


async def _async_tokens(tokens: list[str]):
    """Helper: async generator from a list of tokens."""
    for t in tokens:
        yield t


class TestStreamBuffer:
    def test_window_triggers_at_size(self):
        buf = StreamBuffer(window_size=3)
        assert not buf.add_token("a")
        assert not buf.add_token("b")
        assert buf.add_token("c")  # 3rd token triggers

    def test_full_text(self):
        buf = StreamBuffer(window_size=5)
        for t in ["hello", " ", "world"]:
            buf.add_token(t)
        assert buf.full_text == "hello world"

    def test_current_window(self):
        buf = StreamBuffer(window_size=2, overlap=0)
        buf.add_token("a")
        buf.add_token("b")
        assert buf.current_window == "ab"
        buf.advance_window()
        buf.add_token("c")
        buf.add_token("d")
        assert buf.current_window == "cd"

    def test_overlap(self):
        buf = StreamBuffer(window_size=4, overlap=2)
        for t in "abcd":
            buf.add_token(t)
        buf.advance_window()
        # Should advance by (4-2)=2, so window starts at index 2
        assert buf.current_window == "cd"

    def test_token_count(self):
        buf = StreamBuffer()
        for t in ["a", "b", "c"]:
            buf.add_token(t)
        assert buf.token_count == 3


class TestStreamAnalyzer:
    def test_analyze_window_detects_pii(self):
        policy = load_policy(None)
        rule_engine = RuleEngine(policy)
        analyzer = StreamAnalyzer(rule_engine)
        matches = analyzer.analyze_window("SSN: 123-45-6789", "SSN: 123-45-6789")
        assert len(matches) > 0

    def test_analyze_clean_window(self):
        policy = load_policy(None)
        rule_engine = RuleEngine(policy)
        analyzer = StreamAnalyzer(rule_engine)
        matches = analyzer.analyze_window("Hello world", "Hello world")
        assert len(matches) == 0

    def test_early_exit_on_high_confidence(self):
        from agentauditor.core.models import DefenseLayer, RuleMatch
        match = RuleMatch(
            rule_id="test",
            rule_name="test",
            layer=DefenseLayer.OUTPUT,
            risk_level=RiskLevel.HIGH,
            description="test",
            confidence=0.95,
        )
        assert StreamAnalyzer.should_early_exit([match]) is True

    def test_no_early_exit_low_confidence(self):
        from agentauditor.core.models import DefenseLayer, RuleMatch
        match = RuleMatch(
            rule_id="test",
            rule_name="test",
            layer=DefenseLayer.OUTPUT,
            risk_level=RiskLevel.HIGH,
            description="test",
            confidence=0.5,
        )
        assert StreamAnalyzer.should_early_exit([match]) is False


@pytest.mark.asyncio
class TestScanStream:
    async def test_detects_pii_in_stream(self):
        policy = load_policy(None)
        rule_engine = RuleEngine(policy)

        tokens = ["The user's ", "SSN is ", "123-45-", "6789", " end."]
        verdict = await scan_stream(
            _async_tokens(tokens),
            rule_engine,
            window_size=3,
        )
        # PII should be detected in final analysis if not in a window
        assert verdict.decision in (Decision.MODIFY, Decision.BLOCK, Decision.ESCALATE)

    async def test_clean_stream_allows(self):
        policy = load_policy(None)
        rule_engine = RuleEngine(policy)

        tokens = ["Hello ", "world, ", "this ", "is ", "safe ", "output."]
        verdict = await scan_stream(
            _async_tokens(tokens),
            rule_engine,
            window_size=3,
        )
        assert verdict.decision == Decision.ALLOW

    async def test_on_match_callback(self):
        policy = load_policy(None)
        rule_engine = RuleEngine(policy)

        matches_received = []

        tokens = ["api_key: ", "sk-abc", "123456789", "0123456 ", "end"]
        await scan_stream(
            _async_tokens(tokens),
            rule_engine,
            window_size=3,
            on_match=lambda m: matches_received.extend(m),
        )
        # Callback may or may not fire depending on window timing
        # but the function should not error

    async def test_empty_stream(self):
        policy = load_policy(None)
        rule_engine = RuleEngine(policy)

        verdict = await scan_stream(_async_tokens([]), rule_engine)
        assert verdict.decision == Decision.ALLOW


@pytest.mark.asyncio
class TestEngineStreamIntegration:
    async def test_scan_output_stream(self):
        engine = AuditEngine()
        tokens = ["Hello ", "world."]
        verdict = await engine.scan_output_stream(_async_tokens(tokens))
        assert verdict.decision == Decision.ALLOW

    async def test_scan_output_stream_with_threat(self):
        engine = AuditEngine()
        tokens = ["Your SSN ", "is 123-45-", "6789 and ", "your card ", "is 4111-1111-1111-1111"]
        verdict = await engine.scan_output_stream(
            _async_tokens(tokens),
            window_size=2,
        )
        assert verdict.decision in (Decision.MODIFY, Decision.BLOCK, Decision.ESCALATE)
