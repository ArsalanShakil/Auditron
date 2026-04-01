"""Tests for policy versioning and migration."""

import warnings

import pytest

from agentauditor.policies.migrations import (
    CURRENT_POLICY_VERSION,
    MigrationRegistry,
    PolicyVersion,
    get_registry,
)


class TestPolicyVersion:
    def test_parse_full(self):
        v = PolicyVersion("1.2.3")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3

    def test_parse_two_parts(self):
        v = PolicyVersion("1.0")
        assert v.major == 1
        assert v.minor == 0
        assert v.patch == 0

    def test_parse_one_part(self):
        v = PolicyVersion("2")
        assert v.major == 2
        assert v.minor == 0
        assert v.patch == 0

    def test_str(self):
        assert str(PolicyVersion("1.0")) == "1.0.0"
        assert str(PolicyVersion("2.1.3")) == "2.1.3"

    def test_equality(self):
        assert PolicyVersion("1.0.0") == PolicyVersion("1.0.0")
        assert PolicyVersion("1.0") == PolicyVersion("1.0.0")

    def test_ordering(self):
        assert PolicyVersion("1.0.0") < PolicyVersion("1.0.1")
        assert PolicyVersion("1.0.0") < PolicyVersion("1.1.0")
        assert PolicyVersion("1.0.0") < PolicyVersion("2.0.0")
        assert PolicyVersion("2.0.0") > PolicyVersion("1.9.9")

    def test_hash(self):
        s = {PolicyVersion("1.0.0"), PolicyVersion("1.0")}
        assert len(s) == 1


class TestMigrationRegistry:
    def test_same_version_no_migration(self):
        """1.0 and 1.0.0 are semantically equal — no migration needed."""
        registry = get_registry()
        raw = {"version": "1.0", "name": "test"}
        result = registry.migrate(raw, PolicyVersion("1.0"))
        assert result is raw  # No change, same object returned

    def test_no_migration_needed(self):
        registry = MigrationRegistry()
        raw = {"version": str(CURRENT_POLICY_VERSION)}
        result = registry.migrate(raw, CURRENT_POLICY_VERSION)
        assert result is raw  # No change

    def test_future_version_raises(self):
        registry = MigrationRegistry()
        future = PolicyVersion("99.0.0")
        with pytest.raises(ValueError, match="newer than supported"):
            registry.migrate({}, future)

    def test_deprecation_warning_on_old_version(self):
        """A version older than current should trigger a deprecation warning."""
        registry = MigrationRegistry()

        @registry.register("0.9.0", "1.0.0")
        def _migrate(raw):
            return raw

        raw = {"version": "0.9.0", "name": "test"}
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            registry.migrate(raw, PolicyVersion("0.9.0"))
            assert any(issubclass(x.category, DeprecationWarning) for x in w)


class TestGlobalRegistry:
    def test_v1_0_to_v1_0_0_migration_exists(self):
        registry = get_registry()
        assert ("1.0", "1.0.0") in registry._migrations

    def test_load_old_policy_migrates(self):
        from agentauditor.policies.loader import load_policy

        # Default policy has version "1.0" — should auto-migrate
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            policy = load_policy(None)

        assert policy.version  # Should be set
