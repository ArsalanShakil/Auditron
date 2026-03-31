"""YAML policy loader and validator."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from agentauditor.core.models import PolicyConfig

_DEFAULTS_DIR = Path(__file__).parent / "defaults"


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    """Load a policy from a YAML file. Falls back to the built-in default policy."""
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
