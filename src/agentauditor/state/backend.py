"""Abstract state backend for multi-tenant and distributed deployments."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod


class StateBackend(ABC):
    """Interface for externalized state storage.

    All operations are synchronous for simplicity. The InMemoryStateBackend
    provides the same behavior as the original in-process dicts.
    """

    @abstractmethod
    def list_push(self, namespace: str, key: str, value: str, max_len: int = 200) -> None:
        """Append value to a named list, trim to max_len."""
        ...

    @abstractmethod
    def list_range(self, namespace: str, key: str, start: int = 0, end: int = -1) -> list[str]:
        """Get range of values from a named list. end=-1 means all."""
        ...

    @abstractmethod
    def list_len(self, namespace: str, key: str) -> int:
        """Get length of a named list."""
        ...

    @abstractmethod
    def kv_set(self, namespace: str, key: str, value: str) -> None:
        """Set a key-value pair."""
        ...

    @abstractmethod
    def kv_get(self, namespace: str, key: str) -> str | None:
        """Get a value by key."""
        ...

    @abstractmethod
    def kv_delete(self, namespace: str, key: str) -> None:
        """Delete a key-value pair."""
        ...

    @abstractmethod
    def set_with_ttl(self, namespace: str, key: str, value: str, ttl_seconds: int) -> None:
        """Set a value with time-to-live (for lockouts)."""
        ...

    @abstractmethod
    def get_with_ttl(self, namespace: str, key: str) -> str | None:
        """Get a value, returning None if expired."""
        ...

    def now(self) -> float:
        """Return current time. InMemory uses monotonic, Redis uses wall clock."""
        return time.monotonic()

    def close(self) -> None:
        """Clean up resources."""
        pass
