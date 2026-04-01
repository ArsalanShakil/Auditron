"""In-memory audit storage backend using a ring buffer."""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Any

from agentauditor.logging.backends.base import AuditStorageBackend


class InMemoryBackend(AuditStorageBackend):
    """Default backend: stores entries in an in-memory deque.

    This is the same behavior as the original AuditLogger before backends
    were introduced. Entries are lost on process restart.
    """

    def __init__(self, max_size: int = 1000) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)

    def store(self, entry: dict[str, Any]) -> None:
        self._buffer.append(entry)

    def query(
        self,
        agent_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        risk_level: str | None = None,
        decision: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        results = list(self._buffer)

        if agent_id:
            results = [e for e in results if e.get("agent_id") == agent_id]
        if risk_level:
            results = [e for e in results if e.get("risk_level") == risk_level]
        if decision:
            results = [e for e in results if e.get("decision") == decision]
        if start_time:
            iso = start_time.isoformat()
            results = [e for e in results if e.get("timestamp", "") >= iso]
        if end_time:
            iso = end_time.isoformat()
            results = [e for e in results if e.get("timestamp", "") <= iso]

        return results[offset : offset + limit]

    def count(self, **filters: Any) -> int:
        if not filters:
            return len(self._buffer)
        return len(self.query(**filters))
