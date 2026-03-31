"""Rate limiting and anomaly detection for repeated evasion attempts."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from agentauditor.core.models import Decision, DefenseLayer, RiskLevel, RuleMatch


class AnomalyTracker:
    """Tracks per-agent action rates and blocks agents with repeated violations.

    If an agent accumulates max_blocks_per_minute blocked actions within one minute,
    all subsequent actions are blocked for lockout_duration_s seconds.
    """

    def __init__(
        self,
        max_actions_per_minute: int = 60,
        max_blocks_per_minute: int = 5,
        lockout_duration_s: int = 300,
    ) -> None:
        self.max_actions_per_minute = max_actions_per_minute
        self.max_blocks_per_minute = max_blocks_per_minute
        self.lockout_duration_s = lockout_duration_s

        self._action_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._block_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._lockouts: dict[str, float] = {}  # agent_id -> lockout_expiry_time

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
        """Record an action and check if thresholds are exceeded."""
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
