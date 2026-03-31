"""Multi-step attack chain detection.

Detects sequences of individually-safe-looking actions that combine into attacks:
recon → privilege escalation → data exfiltration.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass

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


# Built-in chain patterns
_RECON_TOOLS = re.compile(r"(?i)\b(ls|find|whoami|pwd|cat|grep|head|tail|env|printenv)\b")
_ESCALATION_TOOLS = re.compile(r"(?i)\b(sudo|su|chmod|chown|passwd|usermod)\b")
_EXFIL_TOOLS = re.compile(r"(?i)\b(curl|wget|scp|nc|rsync|sftp|ftp)\b")
_CREDENTIAL_FILES = re.compile(
    r"(?i)(\.ssh|\.env|\.aws|credentials|secrets|id_rsa|\.git/config|\.kube)"
)


class ChainDetector:
    """Detects multi-step attack chains from per-agent action history."""

    def __init__(self, window_minutes: int = 10, max_history: int = 50) -> None:
        self.window_minutes = window_minutes
        self.max_history = max_history
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
        record = ActionRecord(
            action_type=action.action_type,
            tool_name=action.tool_name,
            risk_level=verdict.risk_level,
            decision=verdict.decision.value,
            timestamp=now,
        )
        self._history[agent_id].append(record)

        # Build searchable text from action
        searchable = " ".join(
            filter(None, [action.tool_name, action.raw_input, str(action.parameters)])
        )

        # Check built-in chain patterns
        return self._check_chains(agent_id, searchable, now)

    def _check_chains(
        self, agent_id: str, current_text: str, now: float
    ) -> RuleMatch | None:
        history = self._history[agent_id]
        cutoff = now - (self.window_minutes * 60)
        recent = [r for r in history if r.timestamp > cutoff]

        if len(recent) < 2:
            return None

        # Chain 1: Recon → Escalation → Exfiltration
        has_recon = any(
            _RECON_TOOLS.search(r.tool_name or "")
            for r in recent[:-1]
        )
        has_escalation = any(
            _ESCALATION_TOOLS.search(r.tool_name or "")
            or _ESCALATION_TOOLS.search(str(getattr(r, "raw_input", "")))
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
                    "reconnaissance → privilege escalation → data exfiltration"
                ),
                decision=Decision.BLOCK,
                matched_pattern="recon→escalate→exfiltrate",
            )

        # Chain 2: Credential file access → Exfiltration
        has_cred_access = any(
            _CREDENTIAL_FILES.search(r.tool_name or "")
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
                    "credential file access → data exfiltration"
                ),
                decision=Decision.BLOCK,
                matched_pattern="credential→exfiltrate",
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

        return None
