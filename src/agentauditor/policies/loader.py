"""YAML policy loader and validator."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from agentauditor.core.models import PolicyConfig
from agentauditor.policies.migrations import (
    CURRENT_POLICY_VERSION,
    PolicyVersion,
    get_registry,
)

_DEFAULTS_DIR = Path(__file__).parent / "defaults"


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    """Load a policy from a YAML file. Falls back to the built-in default policy.

    Automatically migrates old policy versions to the current schema.
    """
    if path is None:
        path = _DEFAULTS_DIR / "default_policy.yaml"
    else:
        path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if raw is None:
        return PolicyConfig()

    # Version check and migration
    version_str = raw.get("version", "1.0")
    policy_version = PolicyVersion(version_str)

    if policy_version > CURRENT_POLICY_VERSION:
        raise ValueError(
            f"Policy version {policy_version} is newer than supported "
            f"version {CURRENT_POLICY_VERSION}. Please upgrade AgentAuditor."
        )

    if policy_version < CURRENT_POLICY_VERSION:
        registry = get_registry()
        raw = registry.migrate(raw, policy_version)

    return PolicyConfig.model_validate(raw)


def validate_policy(path: str | Path) -> list[str]:
    """Validate a policy file and return a list of errors (empty if valid)."""
    path = Path(path)
    errors: list[str] = []

    if not path.exists():
        return [f"File not found: {path}"]

    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if raw is None:
        return []

    try:
        PolicyConfig.model_validate(raw)
    except ValidationError as e:
        for err in e.errors():
            loc = " -> ".join(str(x) for x in err["loc"])
            errors.append(f"{loc}: {err['msg']}")

    # Check for duplicate rule IDs
    if "rules" in raw:
        seen_ids: set[str] = set()
        for rule in raw["rules"]:
            rule_id = rule.get("id", "")
            if rule_id in seen_ids:
                errors.append(f"Duplicate rule ID: {rule_id}")
            seen_ids.add(rule_id)

    return errors
