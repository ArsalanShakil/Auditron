"""Deterministic YAML-based rule evaluation engine."""

from __future__ import annotations

import json

from agentauditor.core.models import (
    Action,
    ActionType,
    DefenseLayer,
    PolicyConfig,
    PolicyRule,
    RuleMatch,
)
from agentauditor.core.normalizer import TextNormalizer, normalize_tool_name
from agentauditor.rules.matchers import PatternMatcher


class RuleEngine:
    """Evaluates actions against policy rules. Stateless and fast (<200ms target)."""

    def __init__(self, policy: PolicyConfig) -> None:
        self.policy = policy
        self._matcher = PatternMatcher()
        self._normalizer = TextNormalizer()

    def evaluate(self, action: Action, layers: list[DefenseLayer] | None = None) -> list[RuleMatch]:
        """Run all enabled rules against an action.

        Returns list of matches ordered by risk severity (critical first).
        Optionally filter by specific defense layers.
        """
        matches: list[RuleMatch] = []
        searchable_text = self._build_searchable_text(action)

        for rule in self._rules_for_action(action, layers):
            match = self._match_rule(rule, action, searchable_text)
            if match is not None:
                matches.append(match)

        matches.sort(key=lambda m: m.risk_level.severity, reverse=True)
        return matches

    def _rules_for_action(
        self, action: Action, layers: list[DefenseLayer] | None = None
    ) -> list[PolicyRule]:
        """Filter rules applicable to this action type and optional layer filter."""
        result = []
        for rule in self.policy.rules:
            if not rule.enabled:
                continue
            if layers and rule.layer not in layers:
                continue
            if rule.action_types and action.action_type not in rule.action_types:
                continue
            if rule.tool_names:
                norm_action_tool = normalize_tool_name(action.tool_name or "")
                norm_rule_tools = {normalize_tool_name(t) for t in rule.tool_names}
                if norm_action_tool not in norm_rule_tools:
                    continue
            result.append(rule)
        return result

    def _match_rule(
        self, rule: PolicyRule, action: Action, searchable_text: str
    ) -> RuleMatch | None:
        """Test a single rule against an action. Returns RuleMatch or None."""
        # If rule has no patterns, it matches by structural criteria only
        # (e.g., identity rules that match by layer/action_type)
        if not rule.patterns:
            return None

        for pattern in rule.patterns:
            matched = self._matcher.match(pattern, searchable_text)
            if matched is not None:
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    layer=rule.layer,
                    risk_level=rule.risk_level,
                    description=rule.description,
                    decision=rule.decision,
                    matched_pattern=matched,
                )

        # Check parameter constraints
        if rule.parameter_constraints:
            for key, constraint in rule.parameter_constraints.items():
                value = action.parameters.get(key)
                if value is not None and self._check_constraint(value, constraint):
                    return RuleMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        layer=rule.layer,
                        risk_level=rule.risk_level,
                        description=rule.description,
                        decision=rule.decision,
                        matched_pattern=f"parameter:{key}",
                    )

        return None

    def _build_searchable_text(self, action: Action) -> str:
        """Concatenate relevant fields, then normalize for pattern matching."""
        parts: list[str] = []
        if action.tool_name:
            parts.append(action.tool_name)
        if action.parameters:
            parts.append(json.dumps(action.parameters, default=str))
        if action.raw_input:
            parts.append(action.raw_input)
        if action.raw_output:
            parts.append(action.raw_output)
        raw = " ".join(parts)
        return self._normalizer.normalize(raw).normalized

    @staticmethod
    def _check_constraint(value: object, constraint: object) -> bool:
        """Check if a parameter value matches a constraint."""
        if isinstance(constraint, dict):
            if "not_in" in constraint and value in constraint["not_in"]:
                return True
            if "in" in constraint and value not in constraint["in"]:
                return True
            if "max" in constraint and isinstance(value, (int, float)) and value > constraint["max"]:
                return True
            if "min" in constraint and isinstance(value, (int, float)) and value < constraint["min"]:
                return True
        elif value == constraint:
            return True
        return False
