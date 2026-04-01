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

    async def test_partial_secret_detection(self):
        """A bare secret prefix without a full match should trigger ESCALATE."""
        layer = OutputLayer()
        policy = load_policy()
        # "sk_live_" alone doesn't match the full API key pattern
        action = Action(
            action_type=ActionType.OUTPUT,
            raw_output="Here is your key: sk_live_",
        )
        matches = await layer.analyze(action, policy, [])
        assert len(matches) >= 1
        assert matches[0].rule_id == "output-partial-secret"
        from agentauditor.core.models import Decision
        assert matches[0].decision == Decision.ESCALATE

    async def test_full_secret_not_flagged_as_partial(self):
        """A complete secret that matches the full redaction pattern should not trigger partial."""
        layer = OutputLayer()
        policy = load_policy()
        # Complete GitHub token — should be caught by the full pattern, not partial
        action = Action(
            action_type=ActionType.OUTPUT,
            raw_output="Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        )
        matches = await layer.analyze(action, policy, [])
        # Full match covers the prefix, so partial detection should not fire
        assert not any(m.rule_id == "output-partial-secret" for m in matches)


class TestNewRedactionPatterns:
    def test_redacts_iban(self):
        result = redact_text("IBAN: DE89 3704 0044 0532 0130 00")
        assert "REDACTED" in result

    def test_redacts_international_phone(self):
        result = redact_text("Call +1 555 123 4567 for support")
        assert "REDACTED" in result

    def test_redacts_slack_token(self):
        # Intentionally fake token for testing redaction pattern coverage
        result = redact_text("Token: xoxb-XXXXXXXXXX0-XXXXXXXXXX0-XXXXXXXXXXXXXXXX")
        assert "REDACTED" in result

    def test_redacts_db_connection_string(self):
        result = redact_text("DB: postgresql://user:pass@localhost/mydb")
        assert "REDACTED" in result

    def test_redacts_ec_private_key(self):
        result = redact_text("-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----")
        assert "REDACTED" in result

    def test_redacts_openssh_private_key(self):
        result = redact_text("-----BEGIN OPENSSH PRIVATE KEY-----\ndata")
        assert "REDACTED" in result
