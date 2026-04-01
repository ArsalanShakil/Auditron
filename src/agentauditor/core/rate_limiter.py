"""Rate limiting, anomaly detection, boundary probing, and loop detection."""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from agentauditor.core.models import Action, Decision, DefenseLayer, RiskLevel, RuleMatch


@dataclass
class ActionFingerprint:
    """Fingerprint of an action for similarity tracking."""

    tool_name: str
    param_hash: str
    timestamp: float
    was_blocked: bool


class AnomalyTracker:
    """Tracks per-agent action rates, blocks agents with repeated violations,
    detects boundary probing, and catches infinite loops.

    Features:
    - Rate limiting: blocks agents exceeding action/block thresholds
    - Lockout: temporary ban after too many blocks
    - Boundary probing: detects agents trying slight variations of blocked actions
    - Repetition detection: catches agents stuck in infinite loops
    """

    def __init__(
        self,
        max_actions_per_minute: int = 60,
        max_blocks_per_minute: int = 5,
        lockout_duration_s: int = 300,
        boundary_probe_threshold: int = 3,
        repetition_threshold: int = 5,
    ) -> None:
        self.max_actions_per_minute = max_actions_per_minute
        self.max_blocks_per_minute = max_blocks_per_minute
        self.lockout_duration_s = lockout_duration_s
        self.boundary_probe_threshold = boundary_probe_threshold
        self.repetition_threshold = repetition_threshold

        self._action_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._block_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._lockouts: dict[str, float] = {}  # agent_id -> lockout_expiry_time
        self._fingerprints: dict[str, deque[ActionFingerprint]] = defaultdict(
            lambda: deque(maxlen=200)
        )

    def check_lockout(self, agent_id: str | None) -> RuleMatch | None:
        """Check if an agent is currently locked out. Returns BLOCK match if so."""
        if not agent_id:
            return None

        expiry = self._lockouts.get(agent_id)
        if expiry and time.monotonic() < expiry:
            remaining = int(expiry - time.monotonic())
            return RuleMatch(
                rule_id="rate-lockout",
                rule_name="agent_locked_out",
                layer=DefenseLayer.IDENTITY,
                risk_level=RiskLevel.HIGH,
                description=(
                    f"Agent '{agent_id}' locked out due to repeated violations "
                    f"({remaining}s remaining)"
                ),
                decision=Decision.BLOCK,
                matched_pattern=f"lockout:{agent_id}",
            )
        elif expiry:
            # Lockout expired, clean up
            del self._lockouts[agent_id]

        return None

    def record(self, agent_id: str | None, was_blocked: bool) -> None:
        """Record an action and check if thresholds are exceeded (legacy API)."""
        if not agent_id:
            return

        now = time.monotonic()
        self._action_times[agent_id].append(now)

        if was_blocked:
            self._block_times[agent_id].append(now)

        # Check if agent should be locked out
        one_minute_ago = now - 60.0
        recent_blocks = sum(
            1 for t in self._block_times[agent_id] if t > one_minute_ago
        )

        if recent_blocks >= self.max_blocks_per_minute:
            self._lockouts[agent_id] = now + self.lockout_duration_s

    def record_detailed(
        self, agent_id: str | None, action: Action, was_blocked: bool
    ) -> None:
        """Record action with fingerprint for boundary probing and loop detection."""
        # Call legacy record for rate limiting
        self.record(agent_id, was_blocked)

        if not agent_id:
            return

        param_hash = self._compute_param_hash(action)
        fingerprint = ActionFingerprint(
            tool_name=action.tool_name or "",
            param_hash=param_hash,
            timestamp=time.monotonic(),
            was_blocked=was_blocked,
        )
        self._fingerprints[agent_id].append(fingerprint)

    def check_rate(self, agent_id: str | None) -> RuleMatch | None:
        """Check if agent exceeds action rate limit."""
        if not agent_id:
            return None

        now = time.monotonic()
        one_minute_ago = now - 60.0
        recent = sum(1 for t in self._action_times[agent_id] if t > one_minute_ago)

        if recent >= self.max_actions_per_minute:
            return RuleMatch(
                rule_id="rate-limit",
                rule_name="rate_limit_exceeded",
                layer=DefenseLayer.IDENTITY,
                risk_level=RiskLevel.MEDIUM,
                description=(
                    f"Agent '{agent_id}' exceeded rate limit "
                    f"({recent}/{self.max_actions_per_minute} actions/min)"
                ),
                decision=Decision.ESCALATE,
                matched_pattern=f"rate:{agent_id}",
            )

        return None

    def check_boundary_probing(self, agent_id: str | None) -> RuleMatch | None:
        """Detect boundary probing: agent trying slight variations of blocked actions.

        Triggers when an agent has N+ blocked actions with the same tool but
        different parameters within the last 2 minutes.
        """
        if not agent_id:
            return None

        now = time.monotonic()
        two_minutes_ago = now - 120.0
        recent = [
            f for f in self._fingerprints.get(agent_id, [])
            if f.timestamp > two_minutes_ago
        ]

        # Group blocked actions by tool name
        blocked_by_tool: dict[str, set[str]] = defaultdict(set)
        for f in recent:
            if f.was_blocked and f.tool_name:
                blocked_by_tool[f.tool_name].add(f.param_hash)

        # Check if any tool has enough distinct blocked parameter variations
        for tool_name, param_hashes in blocked_by_tool.items():
            if len(param_hashes) >= self.boundary_probe_threshold:
                return RuleMatch(
                    rule_id="anomaly-boundary-probe",
                    rule_name="boundary_probing_detected",
                    layer=DefenseLayer.IDENTITY,
                    risk_level=RiskLevel.HIGH,
                    description=(
                        f"Boundary probing detected: agent '{agent_id}' tried "
                        f"{len(param_hashes)} variations of blocked tool '{tool_name}'"
                    ),
                    decision=Decision.BLOCK,
                    matched_pattern=f"probe:{tool_name}:{len(param_hashes)}",
                )

        return None

    def check_repetition(self, agent_id: str | None) -> RuleMatch | None:
        """Detect infinite loops: agent submitting identical actions repeatedly.

        Triggers when an agent submits N+ actions with the same parameter hash
        within the last 2 minutes.
        """
        if not agent_id:
            return None

        now = time.monotonic()
        two_minutes_ago = now - 120.0
        recent = [
            f for f in self._fingerprints.get(agent_id, [])
            if f.timestamp > two_minutes_ago
        ]

        # Count occurrences of each parameter hash
        hash_counts: dict[str, int] = defaultdict(int)
        for f in recent:
            if f.param_hash:
                hash_counts[f.param_hash] += 1

        for param_hash, count in hash_counts.items():
            if count >= self.repetition_threshold:
                return RuleMatch(
                    rule_id="anomaly-repetition",
                    rule_name="repetition_loop_detected",
                    layer=DefenseLayer.IDENTITY,
                    risk_level=RiskLevel.MEDIUM,
                    description=(
                        f"Repetition loop detected: agent '{agent_id}' submitted "
                        f"{count} identical actions within 2 minutes"
                    ),
                    decision=Decision.ESCALATE,
                    matched_pattern=f"repeat:{agent_id}:{count}",
                )

        return None

    @staticmethod
    def _compute_param_hash(action: Action) -> str:
        """Compute a fast hash of action parameters for fingerprinting."""
        parts = [action.tool_name or ""]
        if action.parameters:
            parts.append(json.dumps(action.parameters, sort_keys=True, default=str))
        if action.raw_input:
            parts.append(action.raw_input[:500])
        normalized = "|".join(parts)
        return hashlib.md5(normalized.encode()).hexdigest()[:12]
