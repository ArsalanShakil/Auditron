"""Tests for the policy loader."""

import tempfile
from pathlib import Path

import pytest

from agentauditor.core.models import Decision, DefenseLayer
from agentauditor.policies.loader import load_policy, validate_policy


class TestLoadPolicy:
    def test_loads_default_policy(self):
        policy = load_policy()
        assert policy.name == "default"
        assert len(policy.rules) > 0
        assert len(policy.identity_policies) > 0

    def test_loads_custom_yaml(self, tmp_path: Path):
        yaml_content = """
version: "1.0"
name: "custom"
rules:
  - id: test-001
    name: test_rule
    description: A test rule
    layer: input
    risk_level: high
    patterns:
      - type: keyword
        value: "dangerous"
    decision: block
"""
        policy_file = tmp_path / "test_policy.yaml"
        policy_file.write_text(yaml_content)
        policy = load_policy(policy_file)
        assert policy.name == "custom"
        assert len(policy.rules) == 1
        assert policy.rules[0].decision == Decision.BLOCK

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policy("/nonexistent/policy.yaml")

    def test_empty_yaml_returns_defaults(self, tmp_path: Path):
        policy_file = tmp_path / "empty.yaml"
        policy_file.write_text("")
        policy = load_policy(policy_file)
        assert policy.name == "default"


class TestValidatePolicy:
    def test_valid_policy(self):
        from agentauditor.policies.loader import _DEFAULTS_DIR

        errors = validate_policy(_DEFAULTS_DIR / "default_policy.yaml")
        assert len(errors) == 0

    def test_missing_file(self):
        errors = validate_policy("/nonexistent.yaml")
        assert len(errors) == 1
        assert "not found" in errors[0].lower()

    def test_invalid_yaml(self, tmp_path: Path):
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text(": invalid: yaml: {{")
        errors = validate_policy(policy_file)
        assert len(errors) >= 1

    def test_duplicate_rule_ids(self, tmp_path: Path):
        yaml_content = """
rules:
  - id: dup-001
    name: rule1
    description: First
    layer: input
    risk_level: high
  - id: dup-001
    name: rule2
    description: Second
    layer: input
    risk_level: high
"""
        policy_file = tmp_path / "dup.yaml"
        policy_file.write_text(yaml_content)
        errors = validate_policy(policy_file)
        assert any("duplicate" in e.lower() for e in errors)
