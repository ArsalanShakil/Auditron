"""JSONL (JSON Lines) append-only audit storage backend."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from agentauditor.logging.backends.base import AuditStorageBackend


class JSONLBackend(AuditStorageBackend):
    """Append-only JSONL file backend.

    Each audit entry is written as a single JSON line. Suitable for
    log aggregation pipelines (Fluentd, Logstash, etc.).
    """

    def __init__(self, file_path: str | Path = "agentauditor_audit.jsonl") -> None:
        self._file_path = Path(file_path)

    def store(self, entry: dict[str, Any]) -> None:
        with open(self._file_path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

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
        if not self._file_path.exists():
            return []

        results: list[dict[str, Any]] = []
        with open(self._file_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if agent_id and entry.get("agent_id") != agent_id:
                    continue
                if risk_level and entry.get("risk_level") != risk_level:
                    continue
                if decision and entry.get("decision") != decision:
                    continue
                if start_time and entry.get("timestamp", "") < start_time.isoformat():
                    continue
                if end_time and entry.get("timestamp", "") > end_time.isoformat():
                    continue

                results.append(entry)

        return results[offset : offset + limit]

    def count(self, **filters: Any) -> int:
        if not filters:
            if not self._file_path.exists():
                return 0
            with open(self._file_path) as f:
                return sum(1 for line in f if line.strip())
        return len(self.query(**filters))
