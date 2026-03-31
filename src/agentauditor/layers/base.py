"""Base defense layer abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentauditor.core.models import Action, DefenseLayer, PolicyConfig, RuleMatch


class BaseLayer(ABC):
    """Abstract defense layer. Each layer inspects an action and returns rule matches."""

    layer: DefenseLayer

    @abstractmethod
    async def analyze(
        self, action: Action, policy: PolicyConfig, rule_matches: list[RuleMatch]
    ) -> list[RuleMatch]:
        """Analyze an action and return any additional rule matches found.

        Args:
            action: The action to analyze.
            policy: The active policy configuration.
            rule_matches: Rule matches already found by the rule engine for this layer.

        Returns:
            Additional rule matches found by this layer's heuristics.
        """
        ...
