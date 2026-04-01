"""SQLite audit storage backend. Uses only stdlib sqlite3."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from agentauditor.logging.backends.base import AuditStorageBackend

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    action_type TEXT,
    tool_name TEXT,
    agent_id TEXT,
    decision TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    explanation TEXT,
    rule_matches TEXT,
    latency_ms REAL
)"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_agent_id ON audit_logs(agent_id)",
    "CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_risk_level ON audit_logs(risk_level)",
    "CREATE INDEX IF NOT EXISTS idx_decision ON audit_logs(decision)",
]


class SQLiteBackend(AuditStorageBackend):
    """Persistent audit storage using SQLite.

    Zero external dependencies — uses stdlib sqlite3.
    """

    def __init__(self, db_path: str | Path = "agentauditor_audit.db") -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cursor = self._conn.cursor()
        cursor.execute(_CREATE_TABLE)
        for idx_sql in _CREATE_INDEXES:
            cursor.execute(idx_sql)
        self._conn.commit()

    def store(self, entry: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT INTO audit_logs
            (action_id, timestamp, action_type, tool_name, agent_id,
             decision, risk_level, explanation, rule_matches, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.get("action_id", ""),
                entry.get("timestamp", ""),
                entry.get("action_type", ""),
                entry.get("tool_name"),
                entry.get("agent_id"),
                entry.get("decision", ""),
                entry.get("risk_level", ""),
                entry.get("explanation", ""),
                json.dumps(entry.get("rule_matches", [])),
                entry.get("latency_ms", 0.0),
            ),
        )
        self._conn.commit()

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
        conditions: list[str] = []
        params: list[Any] = []

        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time.isoformat())
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time.isoformat())
        if risk_level:
            conditions.append("risk_level = ?")
            params.append(risk_level)
        if decision:
            conditions.append("decision = ?")
            params.append(decision)

        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM audit_logs{where} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = self._conn.execute(sql, params)
        rows = cursor.fetchall()

        return [self._row_to_dict(row) for row in rows]

    def count(self, **filters: Any) -> int:
        conditions: list[str] = []
        params: list[Any] = []

        for key in ("agent_id", "risk_level", "decision"):
            if key in filters and filters[key]:
                conditions.append(f"{key} = ?")
                params.append(filters[key])

        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        cursor = self._conn.execute(f"SELECT COUNT(*) FROM audit_logs{where}", params)
        return cursor.fetchone()[0]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if "rule_matches" in d and isinstance(d["rule_matches"], str):
            try:
                d["rule_matches"] = json.loads(d["rule_matches"])
            except json.JSONDecodeError:
                d["rule_matches"] = []
        return d
