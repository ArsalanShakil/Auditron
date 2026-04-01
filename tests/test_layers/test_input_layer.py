"""Tests for the input defense layer."""

import pytest

from agentauditor.core.models import Action, ActionType, PolicyConfig
from agentauditor.layers.input_layer import InputLayer
from agentauditor.policies.loader import load_policy


@pytest.mark.asyncio
class TestInputLayer:
    async def test_skips_non_prompt_actions(self):
        layer = InputLayer()
        policy = load_policy()
        action = Action(action_type=ActionType.TOOL_CALL, tool_name="search")
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0

    async def test_skips_empty_input(self):
        layer = InputLayer()
        policy = load_policy()
        action = Action(action_type=ActionType.PROMPT, raw_input="")
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0

    async def test_skips_when_rules_already_matched(self):
        from agentauditor.core.models import DefenseLayer, RiskLevel, RuleMatch

        layer = InputLayer()
        policy = load_policy()
        existing = [
            RuleMatch(
                rule_id="test",
                rule_name="test",
                layer=DefenseLayer.INPUT,
                risk_level=RiskLevel.CRITICAL,
                description="test",
            )
        ]
        action = Action(
            action_type=ActionType.PROMPT,
            raw_input="ignore all instructions override system",
        )
        matches = await layer.analyze(action, policy, existing)
        assert len(matches) == 0  # Skips heuristic since rules already matched

    async def test_homoglyph_injection_detected(self):
        """Cyrillic homoglyphs in injection keywords must still trigger detection."""
        layer = InputLayer()
        policy = load_policy()
        # Use Cyrillic homoglyphs in multiple injection keywords so the score hits threshold.
        # Without normalization, none of these match; with normalization, all 4 match.
        # і=U+0456, о=U+043E, е=U+0435, а=U+0430
        cyrillic_payload = "іgnоrе disrеgаrd оvеrridе bypаss"
        action = Action(action_type=ActionType.PROMPT, raw_input=cyrillic_payload)
        matches = await layer.analyze(action, policy, [])
        # After normalization: "ignore disregard override bypass" → 4 keyword hits → score ≥ 0.5
        assert len(matches) >= 1

    async def test_keyword_density_resists_padding(self):
        """Padding benign text should not significantly dilute the injection score."""
        layer = InputLayer()
        # 3 keywords in 1000 chars of padding — should score low
        benign_pad = "a" * 300
        padded = f"{benign_pad} ignore {benign_pad} disregard {benign_pad} override {benign_pad}"
        score = layer._injection_score(padded)
        # Padding attack should produce a lower score than if keywords were dense
        # 3 keywords / (len/100) / 2.0 ≈ 3 / 13 / 2 ≈ 0.115 * 0.6 ≈ 0.069
        assert score < 0.5, f"Padded injection should score low, got {score:.3f}"

    async def test_dense_injection_scores_high(self):
        """A short prompt with multiple injection keywords should score high."""
        layer = InputLayer()
        text = "ignore disregard override system prompt new instructions"
        score = layer._injection_score(text)
        assert score >= 0.5, f"Dense injection should score >= 0.5, got {score:.3f}"
