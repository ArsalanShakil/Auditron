"""Structured audit logging using OpenTelemetry spans and in-memory ring buffer.

Optionally persists verdicts to an append-only JSONL file for durable audit trails.
"""

from __future__ import annotations

import json
from collections import deque
from datetime import timezone
from pathlib import Path

from agentauditor.core.models import Action, Verdict

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        SimpleSpanProcessor,
        ConsoleSpanExporter,
    )

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


class AuditLogger:
    """Structured audit logger with OpenTelemetry spans, in-memory hot cache,
    and pluggable persistent storage backends."""

    def __init__(
        self,
        service_name: str = "agentauditor",
        console_export: bool = False,
        max_buffer_size: int = 1000,
        backend: "AuditStorageBackend | None" = None,
    ) -> None:
        from agentauditor.logging.backends.base import AuditStorageBackend
        from agentauditor.logging.backends.memory import InMemoryBackend

        self._buffer: deque[dict] = deque(maxlen=max_buffer_size)
        self._backend: AuditStorageBackend = backend or InMemoryBackend(max_size=max_buffer_size)
        self._tracer = None

        if _OTEL_AVAILABLE:
            provider = TracerProvider()
            if console_export:
                provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(service_name)

    def log_verdict(self, action: Action, verdict: Verdict) -> None:
        """Log an audit event to the ring buffer, JSONL file, and OpenTelemetry."""
        entry = self._to_dict(action, verdict)
        self._buffer.append(entry)
        self._backend.store(entry)

        if self._tracer:
            with self._tracer.start_as_current_span("audit_verdict") as span:
                span.set_attribute("action.id", action.action_id)
                span.set_attribute("action.type", action.action_type.value)
                span.set_attribute("action.tool_name", action.tool_name or "")
                span.set_attribute("action.agent_id", action.agent_id or "")
                span.set_attribute("verdict.decision", verdict.decision.value)
                span.set_attribute("verdict.risk_level", verdict.risk_level.value)
                span.set_attribute("verdict.latency_ms", verdict.latency_ms)
                span.set_attribute("verdict.explanation", verdict.explanation)
                span.set_attribute("verdict.rule_match_count", len(verdict.rule_matches))

                for i, match in enumerate(verdict.rule_matches):
                    span.add_event(
                        f"rule_match_{i}",
                        attributes={
                            "rule_id": match.rule_id,
                            "rule_name": match.rule_name,
                            "risk_level": match.risk_level.value,
                            "matched_pattern": match.matched_pattern or "",
                        },
                    )

    def _append_to_file(self, entry: dict) -> None:
        """Append a JSONL line to the audit log file. Failures are silent."""
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:  # type: ignore[arg-type]
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass  # Logging must never break the audit pipeline

    def get_recent_logs(self, limit: int = 50) -> list[dict]:
        """Return recent audit log entries from the hot cache (ring buffer)."""
        entries = list(self._buffer)
        return entries[-limit:]

    def query(self, **filters) -> list[dict]:
        """Query the persistent backend with filters.

        Supported filters: agent_id, start_time, end_time, risk_level, decision, limit, offset.
        """
        return self._backend.query(**filters)

    @property
    def total_audits(self) -> int:
        return len(self._buffer)

    @staticmethod
    def _to_dict(action: Action, verdict: Verdict) -> dict:
        return {
            "action_id": action.action_id,
            "timestamp": verdict.timestamp.astimezone(timezone.utc).isoformat(),
            "action_type": action.action_type.value,
            "tool_name": action.tool_name,
            "agent_id": action.agent_id,
            "decision": verdict.decision.value,
            "risk_level": verdict.risk_level.value,
            "explanation": verdict.explanation,
            "rule_matches": [m.model_dump(mode="json") for m in verdict.rule_matches],
            "latency_ms": round(verdict.latency_ms, 2),
        }
