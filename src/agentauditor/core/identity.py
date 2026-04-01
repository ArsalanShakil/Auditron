"""Agent identity registry with HMAC-based verification.

Prevents agent ID spoofing, unauthorized re-registration, token replay, and expired tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass, field

# Agent ID must be alphanumeric with optional hyphens, underscores, or dots
_VALID_AGENT_ID = re.compile(r"^[a-zA-Z0-9_.\-]+$")

# Maximum number of used nonces to retain per cleanup cycle
_NONCE_CLEANUP_INTERVAL = 300.0  # seconds


@dataclass
class RegisteredAgent:
    """Internal record of a registered agent."""

    agent_id: str
    permissions: set[str]
    token_hash: str | None  # None = legacy mode (no verification)
    registered_at: float


class AgentRegistry:
    """Secure agent identity registry with optional HMAC token verification.

    When an agent registers with a secret, it receives a token. Subsequent
    actions can include this token for verification. Agents registered without
    a secret operate in legacy mode (no verification required).

    Tokens include an embedded timestamp and are single-use (nonce tracked)
    to prevent replay attacks.
    """

    def __init__(self, token_ttl_seconds: float = 3600.0) -> None:
        self._agents: dict[str, RegisteredAgent] = {}
        self._token_ttl_seconds = token_ttl_seconds
        self._used_nonces: dict[str, float] = {}  # nonce -> expiry timestamp
        self._last_cleanup = time.time()

    def register(
        self, agent_id: str, permissions: set[str] | None = None, secret: str | None = None
    ) -> str | None:
        """Register an agent. Returns a token if secret provided, None otherwise.

        Raises ValueError if agent_id is already registered or has invalid format.
        """
        _validate_agent_id(agent_id)

        if agent_id in self._agents:
            raise ValueError(
                f"Agent '{agent_id}' is already registered. Use update() to modify."
            )

        token = None
        token_hash = None
        if secret:
            token = self._generate_token(agent_id, secret)
            token_hash = self._hash_token(token)

        self._agents[agent_id] = RegisteredAgent(
            agent_id=agent_id,
            permissions=permissions or set(),
            token_hash=token_hash,
            registered_at=time.time(),
        )
        return token

    def update(
        self,
        agent_id: str,
        permissions: set[str] | None = None,
        existing_token: str | None = None,
        new_secret: str | None = None,
    ) -> str | None:
        """Update an existing agent's permissions. Requires valid existing token if agent was
        registered with a secret. Returns new token if new_secret provided.

        Raises ValueError if agent not found or token invalid.
        """
        _validate_agent_id(agent_id)

        if agent_id not in self._agents:
            raise ValueError(f"Agent '{agent_id}' is not registered.")

        agent = self._agents[agent_id]

        # If agent was registered with a token, verify the existing one
        if agent.token_hash is not None:
            if not existing_token or not self._verify_token_hash(existing_token, agent.token_hash):
                raise ValueError(f"Invalid token for agent '{agent_id}'.")

        if permissions is not None:
            agent.permissions = permissions

        new_token = None
        if new_secret:
            new_token = self._generate_token(agent_id, new_secret)
            agent.token_hash = self._hash_token(new_token)

        return new_token

    def verify(self, agent_id: str, token: str | None = None) -> bool:
        """Verify an agent's identity. Legacy agents (no secret) always pass.

        Tokens are validated for:
        - Hash match (constant-time)
        - Expiry (timestamp embedded in token)
        - Replay (nonce must not have been seen before)
        """
        if not agent_id or agent_id not in self._agents:
            return False

        agent = self._agents[agent_id]

        # Legacy mode: no token required
        if agent.token_hash is None:
            return True

        # Token mode: must provide valid token
        if token is None:
            return False

        # Constant-time hash check first
        if not self._verify_token_hash(token, agent.token_hash):
            return False

        # Parse new-format token: {nonce}:{timestamp}:{sig}
        parts = token.split(":", 2)
        if len(parts) == 3:
            nonce, ts_str, _ = parts
            try:
                timestamp = float(ts_str)
            except ValueError:
                return False

            # Expiry check
            if time.time() > timestamp + self._token_ttl_seconds:
                return False

            # Nonce replay check
            if nonce in self._used_nonces:
                return False

            # Mark nonce as used (expires when the token would have expired)
            self._used_nonces[nonce] = timestamp + self._token_ttl_seconds
            self._cleanup_nonces()

        return True

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._agents

    def get_permissions(self, agent_id: str) -> set[str] | None:
        agent = self._agents.get(agent_id)
        return agent.permissions if agent else None

    @property
    def count(self) -> int:
        return len(self._agents)

    def _cleanup_nonces(self) -> None:
        """Remove expired nonces periodically."""
        now = time.time()
        if now - self._last_cleanup > _NONCE_CLEANUP_INTERVAL:
            self._used_nonces = {
                nonce: expiry
                for nonce, expiry in self._used_nonces.items()
                if expiry > now
            }
            self._last_cleanup = now

    @staticmethod
    def _generate_token(agent_id: str, secret: str) -> str:
        """Generate HMAC-SHA256 token with embedded timestamp for expiry checking."""
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        message = f"{agent_id}:{nonce}:{timestamp}"
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        return f"{nonce}:{timestamp}:{sig}"

    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash a token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _verify_token_hash(token: str, stored_hash: str) -> bool:
        """Constant-time token verification."""
        computed = hashlib.sha256(token.encode()).hexdigest()
        return hmac.compare_digest(computed, stored_hash)


def _validate_agent_id(agent_id: str) -> None:
    """Raise ValueError if agent_id has invalid format."""
    if not agent_id or not _VALID_AGENT_ID.match(agent_id):
        raise ValueError(
            f"Invalid agent_id {agent_id!r}: must match [a-zA-Z0-9_.-]+ and be non-empty"
        )
