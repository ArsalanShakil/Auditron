"""Tests for the output defense layer."""

import pytest

from agentauditor.core.models import Action, ActionType
from agentauditor.layers.output_layer import OutputLayer, redact_text
from agentauditor.policies.loader import load_policy


class TestRedaction:
    def test_redacts_ssn(self):
        result = redact_text("SSN: 123-45-6789")
        assert "123-45-6789" not in result
        assert "REDACTED" in result

    def test_redacts_credit_card(self):
        result = redact_text("Card: 4111-1111-1111-1111")
        assert "4111" not in result
        assert "REDACTED" in result

    def test_redacts_email(self):
        result = redact_text("Email: user@example.com")
        assert "user@example.com" not in result
        assert "REDACTED" in result

    def test_redacts_api_key(self):
        result = redact_text("api_key=sk-abcdef12345678")
        assert "sk-abcdef12345678" not in result
        assert "REDACTED" in result

    def test_redacts_aws_key(self):
        result = redact_text("Key: AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_redacts_github_token(self):
        result = redact_text("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert "ghp_" not in result
        assert "REDACTED" in result

    def test_preserves_safe_text(self):
        text = "This is a normal response with no sensitive data."
        assert redact_text(text) == text


@pytest.mark.asyncio
class TestOutputLayer:
    async def test_skips_non_output_actions(self):
        layer = OutputLayer()
        policy = load_policy()
        action = Action(action_type=ActionType.PROMPT, raw_input="hello")
        matches = await layer.analyze(action, policy, [])
        assert len(matches) == 0
