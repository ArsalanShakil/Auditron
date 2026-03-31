"""Tests for the agent identity registry."""

import pytest

from agentauditor.core.identity import AgentRegistry


class TestAgentRegistry:
    def test_register_without_secret(self):
        registry = AgentRegistry()
        token = registry.register("agent-1", {"read"})
        assert token is None
        assert registry.is_registered("agent-1")

    def test_register_with_secret(self):
        registry = AgentRegistry()
        token = registry.register("agent-1", {"read"}, secret="my-secret")
        assert token is not None
        assert ":" in token  # nonce:signature format
        assert registry.is_registered("agent-1")

    def test_verify_valid_token(self):
        registry = AgentRegistry()
        token = registry.register("agent-1", {"read"}, secret="my-secret")
        assert registry.verify("agent-1", token)

    def test_verify_invalid_token(self):
        registry = AgentRegistry()
        registry.register("agent-1", {"read"}, secret="my-secret")
        assert not registry.verify("agent-1", "bad-token")

    def test_verify_missing_token_for_secured_agent(self):
        registry = AgentRegistry()
        registry.register("agent-1", {"read"}, secret="my-secret")
        assert not registry.verify("agent-1", None)

    def test_verify_legacy_agent_no_token_needed(self):
        registry = AgentRegistry()
        registry.register("agent-1", {"read"})
        assert registry.verify("agent-1")
        assert registry.verify("agent-1", None)
        assert registry.verify("agent-1", "any-token")

    def test_verify_unregistered_agent(self):
        registry = AgentRegistry()
        assert not registry.verify("unknown")

    def test_duplicate_registration_raises(self):
        registry = AgentRegistry()
        registry.register("agent-1", {"read"})
        with pytest.raises(ValueError, match="already registered"):
            registry.register("agent-1", {"write"})

    def test_update_with_valid_token(self):
        registry = AgentRegistry()
        token = registry.register("agent-1", {"read"}, secret="s1")
        new_token = registry.update("agent-1", {"read", "write"}, existing_token=token)
        assert registry.get_permissions("agent-1") == {"read", "write"}

    def test_update_with_invalid_token_raises(self):
        registry = AgentRegistry()
        registry.register("agent-1", {"read"}, secret="s1")
        with pytest.raises(ValueError, match="Invalid token"):
            registry.update("agent-1", {"write"}, existing_token="bad")

    def test_update_unregistered_raises(self):
        registry = AgentRegistry()
        with pytest.raises(ValueError, match="not registered"):
            registry.update("unknown", {"read"})

    def test_count(self):
        registry = AgentRegistry()
        assert registry.count == 0
        registry.register("a1")
        registry.register("a2")
        assert registry.count == 2

    def test_get_permissions(self):
        registry = AgentRegistry()
        registry.register("agent-1", {"read", "write"})
        assert registry.get_permissions("agent-1") == {"read", "write"}
        assert registry.get_permissions("unknown") is None
