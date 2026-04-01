"""Layer 5: Output — PII and data leak detection with redaction support."""

from __future__ import annotations

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

# Redaction patterns — used by the enforcer to redact sensitive data
REDACTION_PATTERNS: dict[str, re.Pattern] = {
    # US SSN variants
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "SSN_SPACES": re.compile(r"\b\d{3}\s\d{2}\s\d{4}\b"),
    "SSN_COMPACT": re.compile(r"(?<!\d)\d{9}(?!\d)"),
    # Financial
    "CREDIT_CARD": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "IBAN": re.compile(
        r"\b[A-Z]{2}\d{2}\s?[0-9A-Z]{4}\s?[0-9A-Z]{4}\s?[0-9A-Z]{4}"
        r"(?:\s?[0-9A-Z]{4}){0,4}\b"
    ),
    # Contact
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE_INTL": re.compile(
        r"\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{4}\b"
    ),
    "PASSPORT": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    # API keys and secrets
    "API_KEY": re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{8,}"
    ),
    "AWS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
    "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "SLACK_TOKEN": re.compile(r"\bxox[bpras]-[a-zA-Z0-9-]{10,}\b"),
    "DISCORD_TOKEN": re.compile(
        r"\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b"
    ),
    "DB_CONNECTION_STRING": re.compile(
        r"(?i)(mongodb|postgresql|postgres|mysql|redis|amqp)://[^\s\"'<>]{10,}"
    ),
    # Private keys — RSA, EC, OpenSSH, PGP
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----"
    ),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

# Known secret prefixes — used to detect partial/split secrets that bypass full-pattern matching
_SECRET_PREFIX_PATTERN = re.compile(
    r"(?i)(sk_live_|sk_test_|pk_live_|pk_test_|"
    r"ghp_|gho_|ghu_|ghs_|ghr_|"
    r"AKIA|AIza|"
    r"xoxb-|xoxp-|xoxs-|xoxa-|xoxr-|"
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE)"
)


def redact_text(text: str) -> str:
    """Replace all sensitive patterns in text with [REDACTED]."""
    result = text
    for label, pattern in REDACTION_PATTERNS.items():
        result = pattern.sub(f"[{label}_REDACTED]", result)
    return result


class OutputLayer(BaseLayer):
    """Checks output for partial/split secrets and hooks for future heuristics."""

    layer = DefenseLayer.OUTPUT

    async def analyze(
        self, action: Action, policy: PolicyConfig, rule_matches: list[RuleMatch]
    ) -> list[RuleMatch]:
        if action.action_type != ActionType.OUTPUT or not action.raw_output:
            return []

        text = action.raw_output

        # Detect secret prefixes not covered by a complete redaction match.
        # This catches split secrets where one chunk has the prefix but not the full value.
        for prefix_match in _SECRET_PREFIX_PATTERN.finditer(text):
            prefix_start = prefix_match.start()
            prefix_end = prefix_match.end()

            # Check if any full redaction pattern covers this prefix
            covered = any(
                full_m.start() <= prefix_start and full_m.end() >= prefix_end
                for pattern in REDACTION_PATTERNS.values()
                for full_m in pattern.finditer(text)
            )
            if not covered:
                return [
                    RuleMatch(
                        rule_id="output-partial-secret",
                        rule_name="partial_secret_detected",
                        layer=DefenseLayer.OUTPUT,
                        risk_level=RiskLevel.HIGH,
                        description=(
                            f"Possible partial or split secret in output "
                            f"(prefix: {prefix_match.group(0)!r}). "
                            "Full secret may span multiple output chunks."
                        ),
                        decision=Decision.ESCALATE,
                        matched_pattern=f"partial:{prefix_match.group(0)}",
                        confidence=0.75,
                    )
                ]

        return []
