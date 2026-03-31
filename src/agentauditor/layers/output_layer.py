"""Layer 5: Output — PII and data leak detection with redaction support."""

from __future__ import annotations

import re

from agentauditor.core.models import (
    Action,
    ActionType,
    DefenseLayer,
    PolicyConfig,
    RuleMatch,
)
from agentauditor.layers.base import BaseLayer

# Redaction patterns — used by the enforcer to redact sensitive data
REDACTION_PATTERNS: dict[str, re.Pattern] = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "SSN_SPACES": re.compile(r"\b\d{3}\s\d{2}\s\d{4}\b"),
    "SSN_COMPACT": re.compile(r"(?<!\d)\d{9}(?!\d)"),
    "CREDIT_CARD": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "API_KEY": re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{8,}"
    ),
    "AWS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
    "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}


def redact_text(text: str) -> str:
    """Replace all sensitive patterns in text with [REDACTED]."""
    result = text
    for label, pattern in REDACTION_PATTERNS.items():
        result = pattern.sub(f"[{label}_REDACTED]", result)
    return result


class OutputLayer(BaseLayer):
    """Detects PII and secrets in agent output. Rule engine handles detection;
    this layer is a hook for additional output analysis."""

    layer = DefenseLayer.OUTPUT

    async def analyze(
        self, action: Action, policy: PolicyConfig, rule_matches: list[RuleMatch]
    ) -> list[RuleMatch]:
        if action.action_type != ActionType.OUTPUT or not action.raw_output:
            return []

        # Rule engine already handles pattern detection for this layer.
        # This layer is a hook for future heuristics (NER-based PII, etc.)
        return []
