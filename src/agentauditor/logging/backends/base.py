"""Abstract base class for audit storage backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any


class AuditStorageBackend(ABC):
    """Interface for audit log storage."""

    @abstractmethod
    def store(self, entry: dict[str, Any]) -> None:
        """Store a single audit log entry."""
        ...

    @abstractmethod
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
        """Query audit logs with optional filters."""
        ...

    @abstractmethod
    def count(self, **filters: Any) -> int:
        """Count entries matching filters."""
        ...

    def close(self) -> None:
        """Clean up resources. Override if needed."""
        pass
