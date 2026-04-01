"""Tests for state backend abstraction."""

import time

import pytest

from agentauditor.state.memory import InMemoryStateBackend


class TestInMemoryStateBackend:
    def test_list_push_and_range(self):
        backend = InMemoryStateBackend()
        backend.list_push("ns", "key", "a")
        backend.list_push("ns", "key", "b")
        backend.list_push("ns", "key", "c")
        assert backend.list_range("ns", "key") == ["a", "b", "c"]

    def test_list_max_len(self):
        backend = InMemoryStateBackend()
        for i in range(10):
            backend.list_push("ns", "key", str(i), max_len=3)
        assert backend.list_len("ns", "key") == 3
        assert backend.list_range("ns", "key") == ["7", "8", "9"]

    def test_list_range_slice(self):
        backend = InMemoryStateBackend()
        for i in range(5):
            backend.list_push("ns", "key", str(i))
        assert backend.list_range("ns", "key", 1, 3) == ["1", "2"]

    def test_list_len(self):
        backend = InMemoryStateBackend()
        backend.list_push("ns", "key", "a")
        backend.list_push("ns", "key", "b")
        assert backend.list_len("ns", "key") == 2

    def test_list_empty(self):
        backend = InMemoryStateBackend()
        assert backend.list_range("ns", "nonexistent") == []
        assert backend.list_len("ns", "nonexistent") == 0

    def test_kv_set_and_get(self):
        backend = InMemoryStateBackend()
        backend.kv_set("ns", "key", "value")
        assert backend.kv_get("ns", "key") == "value"

    def test_kv_get_missing(self):
        backend = InMemoryStateBackend()
        assert backend.kv_get("ns", "missing") is None

    def test_kv_delete(self):
        backend = InMemoryStateBackend()
        backend.kv_set("ns", "key", "value")
        backend.kv_delete("ns", "key")
        assert backend.kv_get("ns", "key") is None

    def test_kv_delete_missing_no_error(self):
        backend = InMemoryStateBackend()
        backend.kv_delete("ns", "nonexistent")  # Should not raise

    def test_set_with_ttl(self):
        backend = InMemoryStateBackend()
        backend.set_with_ttl("ns", "key", "value", ttl_seconds=10)
        assert backend.get_with_ttl("ns", "key") == "value"

    def test_ttl_expiration(self):
        backend = InMemoryStateBackend()
        backend.set_with_ttl("ns", "key", "value", ttl_seconds=0)
        # TTL of 0 means already expired
        time.sleep(0.01)
        assert backend.get_with_ttl("ns", "key") is None

    def test_ttl_missing_key(self):
        backend = InMemoryStateBackend()
        assert backend.get_with_ttl("ns", "missing") is None

    def test_namespace_isolation(self):
        backend = InMemoryStateBackend()
        backend.kv_set("tenant-a", "key", "a")
        backend.kv_set("tenant-b", "key", "b")
        assert backend.kv_get("tenant-a", "key") == "a"
        assert backend.kv_get("tenant-b", "key") == "b"

    def test_list_namespace_isolation(self):
        backend = InMemoryStateBackend()
        backend.list_push("tenant-a", "actions", "1")
        backend.list_push("tenant-b", "actions", "2")
        assert backend.list_range("tenant-a", "actions") == ["1"]
        assert backend.list_range("tenant-b", "actions") == ["2"]

    def test_now_returns_monotonic(self):
        backend = InMemoryStateBackend()
        t1 = backend.now()
        t2 = backend.now()
        assert t2 >= t1


class TestRedisBackendImport:
    def test_import_without_redis(self):
        """RedisStateBackend should raise ImportError if redis not installed."""
        try:
            from agentauditor.state.redis import RedisStateBackend
            # If redis IS installed, just verify the class exists
            assert RedisStateBackend is not None
        except ImportError:
            pass  # Expected if redis not installed
