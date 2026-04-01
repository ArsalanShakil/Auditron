"""Redis state backend for distributed/multi-tenant deployments.

Requires: pip install agentauditor[redis]
"""

from __future__ import annotations

import time

from agentauditor.state.backend import StateBackend

try:
    import redis

    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class RedisStateBackend(StateBackend):
    """Redis-backed state for distributed deployments.

    Maps operations to Redis commands:
    - list_push → RPUSH + LTRIM
    - list_range → LRANGE
    - kv_set/get → SET/GET
    - set_with_ttl → SETEX
    """

    def __init__(self, url: str = "redis://localhost:6379/0") -> None:
        if not _AVAILABLE:
            raise ImportError(
                "redis package required. Install with: pip install agentauditor[redis]"
            )
        self._client = redis.Redis.from_url(url, decode_responses=True)

    def list_push(self, namespace: str, key: str, value: str, max_len: int = 200) -> None:
        full_key = f"{namespace}:{key}"
        pipe = self._client.pipeline()
        pipe.rpush(full_key, value)
        pipe.ltrim(full_key, -max_len, -1)
        pipe.execute()

    def list_range(self, namespace: str, key: str, start: int = 0, end: int = -1) -> list[str]:
        return self._client.lrange(f"{namespace}:{key}", start, end)

    def list_len(self, namespace: str, key: str) -> int:
        return self._client.llen(f"{namespace}:{key}")

    def kv_set(self, namespace: str, key: str, value: str) -> None:
        self._client.set(f"{namespace}:{key}", value)

    def kv_get(self, namespace: str, key: str) -> str | None:
        return self._client.get(f"{namespace}:{key}")

    def kv_delete(self, namespace: str, key: str) -> None:
        self._client.delete(f"{namespace}:{key}")

    def set_with_ttl(self, namespace: str, key: str, value: str, ttl_seconds: int) -> None:
        self._client.setex(f"{namespace}:{key}", ttl_seconds, value)

    def get_with_ttl(self, namespace: str, key: str) -> str | None:
        return self._client.get(f"{namespace}:{key}")

    def now(self) -> float:
        return time.time()

    def close(self) -> None:
        self._client.close()
