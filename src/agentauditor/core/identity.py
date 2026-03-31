"""Agent identity registry with HMAC-based verification.

Prevents agent ID spoofing and unauthorized re-registration.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field


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
    """

    def __init__(self) -> None:
        self._agents: dict[str, RegisteredAgent] = {}

    def register(
        self, agent_id: str, permissions: set[str] | None = None, secret: str | None = None
    ) -> str | None:
        """Register an agent. Returns a token if secret provided, None otherwise.

        Raises ValueError if agent_id is already registered.
        """
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
        """Verify an agent's identity. Legacy agents (no secret) always pass."""
        if agent_id not in self._agents:
            return False

        agent = self._agents[agent_id]

        # Legacy mode: no token required
        if agent.token_hash is None:
            return True

        # Token mode: must provide valid token
        if token is None:
            return False

        return self._verify_token_hash(token, agent.token_hash)

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._agents

    def get_permissions(self, agent_id: str) -> set[str] | None:
        agent = self._agents.get(agent_id)
        return agent.permissions if agent else None

    @property
    def count(self) -> int:
        return len(self._agents)

    @staticmethod
    def _generate_token(agent_id: str, secret: str) -> str:
        """Generate HMAC-SHA256 token."""
        nonce = secrets.token_hex(16)
        message = f"{agent_id}:{nonce}:{time.time()}"
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        return f"{nonce}:{sig}"

    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash a token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _verify_token_hash(token: str, stored_hash: str) -> bool:
        """Constant-time token verification."""
        computed = hashlib.sha256(token.encode()).hexdigest()
        return hmac.compare_digest(computed, stored_hash)
