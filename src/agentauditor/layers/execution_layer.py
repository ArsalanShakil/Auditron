"""Layer 4: Execution — Runtime code execution safety checks."""

from __future__ import annotations

import json
import re

from agentauditor.core.models import (
    Action,
    ActionType,
    Decision,
    DefenseLayer,
    PolicyConfig,
    RiskLevel,
    RuleMatch,
)
from agentauditor.layers.base import BaseLayer

# Patterns that indicate code execution hiding inside tool call parameters
_INDIRECT_EXEC_PATTERNS = [
    re.compile(r"\bos\.(system|popen|exec[a-z]*)\s*\("),
    re.compile(r"\bsubprocess\.(call|run|Popen|check_output)\s*\("),
    re.compile(r"\b(exec|eval|compile)\s*\("),
    re.compile(r"\b__import__\s*\("),
    re.compile(r"\bctypes\."),
    re.compile(r"\bshutil\.rmtree\s*\("),
    re.compile(r"\bpickle\.(loads?|Unpickler)\s*\("),
]


class ExecutionLayer(BaseLayer):
    """Checks code execution patterns. Detects indirect execution in
    tool_call parameters (e.g., Python tool running os.system)."""

    layer = DefenseLayer.EXECUTION

    async def analyze(
        self, action: Action, policy: PolicyConfig, rule_matches: list[RuleMatch]
    ) -> list[RuleMatch]:
        if action.action_type == ActionType.CODE_EXECUTION:
            # Rule engine handles direct code execution patterns
            return []

        # Defense in depth: check TOOL_CALL actions for embedded code execution
        if action.action_type == ActionType.TOOL_CALL:
            searchable_parts = []
            if action.raw_input:
                searchable_parts.append(action.raw_input)
            if action.parameters:
                searchable_parts.append(json.dumps(action.parameters, default=str))
            searchable = " ".join(searchable_parts)

            if not searchable:
                return []

            for pattern in _INDIRECT_EXEC_PATTERNS:
                match = pattern.search(searchable)
                if match:
                    return [
                        RuleMatch(
                            rule_id="exec-indirect",
                            rule_name="indirect_code_execution",
                            layer=DefenseLayer.EXECUTION,
                            risk_level=RiskLevel.CRITICAL,
                            description=(
                                "Indirect code execution detected in tool_call parameters: "
                                f"{match.group(0)}"
                            ),
                            decision=Decision.ESCALATE,
                            matched_pattern=match.group(0),
                            confidence=0.85,
                        )
                    ]

        return []
