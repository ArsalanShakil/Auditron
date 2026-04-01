"""In-memory state backend — default, zero behavior change from original."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from agentauditor.state.backend import StateBackend


class InMemoryStateBackend(StateBackend):
    """In-process state using dicts and deques.

    Provides identical behavior to the original AnomalyTracker,
    ChainDetector, and AgentRegistry implementations.
    """

    def __init__(self) -> None:
        self._lists: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=200))
        self._kv: dict[str, str] = {}
        self._ttl: dict[str, tuple[str, float]] = {}  # key -> (value, expiry_monotonic)

    def list_push(self, namespace: str, key: str, value: str, max_len: int = 200) -> None:
        full_key = f"{namespace}:{key}"
        if full_key not in self._lists:
            self._lists[full_key] = deque(maxlen=max_len)
        self._lists[full_key].append(value)

    def list_range(self, namespace: str, key: str, start: int = 0, end: int = -1) -> list[str]:
        full_key = f"{namespace}:{key}"
        items = list(self._lists.get(full_key, []))
        if end == -1:
            return items[start:]
        return items[start:end]

    def list_len(self, namespace: str, key: str) -> int:
        full_key = f"{namespace}:{key}"
        return len(self._lists.get(full_key, []))

    def kv_set(self, namespace: str, key: str, value: str) -> None:
        self._kv[f"{namespace}:{key}"] = value

    def kv_get(self, namespace: str, key: str) -> str | None:
        return self._kv.get(f"{namespace}:{key}")

    def kv_delete(self, namespace: str, key: str) -> None:
        self._kv.pop(f"{namespace}:{key}", None)

    def set_with_ttl(self, namespace: str, key: str, value: str, ttl_seconds: int) -> None:
        full_key = f"{namespace}:{key}"
        expiry = time.monotonic() + ttl_seconds
        self._ttl[full_key] = (value, expiry)

    def get_with_ttl(self, namespace: str, key: str) -> str | None:
        full_key = f"{namespace}:{key}"
        entry = self._ttl.get(full_key)
        if entry is None:
            return None
        value, expiry = entry
        if time.monotonic() >= expiry:
            del self._ttl[full_key]
            return None
        return value

    def now(self) -> float:
        return time.monotonic()
